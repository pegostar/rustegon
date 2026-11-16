// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.rdoc.RDocument;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Runs the operations of conformance tests (drivers/conformance/README.md §5) against a client:
 * dispatch by object and name, argument conversion, result normalisation into documents and
 * lists, expectations ({@code result} with {@code exact}/{@code subset}, {@code error} with
 * class, code, name and flags), {@code saveAs} and {@code $$ref}. Fixture-specific behaviour
 * (opening clients, runner operations) comes from the {@link Env}.
 */
final class OpRunner {
    /** What the fixture provides. */
    interface Env {
        /** {@code ${…}} substitutions. */
        String substitute(String s);

        /** {@code client.open}: a client for {@code args} (not yet connected). */
        RustegonClient open(Map<String, Object> args, OpRunner runner);

        /** {@code runner.<name>}; returns the operation's result. */
        Object runner(String name, Map<String, Object> args, OpRunner runner) throws Exception;
    }

    /** The exception of {@code runner.throwApplicationError}. */
    static final class ApplicationError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        ApplicationError() {
            super("application error thrown by the callback");
        }
    }

    /** errors-map.yaml class ids, most specific first. */
    private static final Map<String, Class<?>> CLASSES = new LinkedHashMap<>();

    static {
        CLASSES.put("PasswordChangeRequired", PasswordChangeRequiredException.class);
        CLASSES.put("QuerySyntax", QuerySyntaxException.class);
        CLASSES.put("Client", RustegonClientException.class);
        CLASSES.put("DuplicateKey", DuplicateKeyException.class);
        CLASSES.put("DocumentValidation", DocumentValidationException.class);
        CLASSES.put("TransactionConflict", TransactionConflictException.class);
        CLASSES.put("TransactionAborted", TransactionAbortedException.class);
        CLASSES.put("CommitOutcomeUnknown", CommitOutcomeUnknownException.class);
        CLASSES.put("Authentication", AuthenticationException.class);
        CLASSES.put("Authorization", AuthorizationException.class);
        CLASSES.put("Unavailable", UnavailableException.class);
        CLASSES.put("RateLimited", RateLimitedException.class);
        CLASSES.put("Timeout", RustegonTimeoutException.class);
        CLASSES.put("Server", RustegonServerException.class);
        CLASSES.put("Base", RustegonException.class);
        CLASSES.put("Argument", IllegalArgumentException.class);
        CLASSES.put("InvalidState", IllegalStateException.class);
    }

    final RustegonClient client;
    final String database;
    final String defaultCollection;
    final Env env;
    final Map<String, Object> saved = new HashMap<>();
    final List<Map<String, Object>> observations = new ArrayList<>();
    private final Deque<Transaction> transactions = new ArrayDeque<>();
    private final List<AutoCloseable> opened = new ArrayList<>();
    private Throwable lastError;
    private int index;
    private int depth;

    OpRunner(RustegonClient client, String database, String defaultCollection, Env env) {
        this.client = client;
        this.database = database;
        this.defaultCollection = defaultCollection;
        this.env = env;
    }

    /** Closes the clients, sessions, cursors and transactions the operations opened. */
    void closeOpened() {
        for (AutoCloseable c : opened) {
            try {
                c.close();
            } catch (Exception e) {
                // cleanup only
            }
        }
        opened.clear();
    }

    Object v(Object yaml) {
        return ConformanceValues.value(yaml, this::ref, env::substitute);
    }

    private Object ref(String spec) {
        String[] parts = spec.split("\\.");
        if (!saved.containsKey(parts[0])) {
            throw new AssertionError("$$ref to an unsaved name: " + spec);
        }
        Object x = saved.get(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            x = ((Map<?, ?>) x).get(parts[i]);
        }
        return x;
    }

    /**
     * Runs one operation and checks its expectation; an exception of an operation without
     * {@code expect} propagates (inside a {@code withTransaction} callback that is how a failure
     * reaches the helper).
     */
    void run(Map<String, Object> op) throws Exception {
        // Only top-level operations are observed, numbered by their position (README §6);
        // callback and step operations are checked by their own expectations.
        int at = depth == 0 ? index++ : -1;
        depth++;
        try {
            run(op, at);
        } finally {
            depth--;
        }
    }

    @SuppressWarnings("unchecked")
    private void run(Map<String, Object> op, int at) throws Exception {
        String where = at >= 0 ? "op " + at : "callback op";
        Map<String, Object> expect = (Map<String, Object>) op.get("expect");
        Object result;
        try {
            result = invoke(op);
        } catch (Exception | AssertionError e) {
            if (e instanceof AssertionError a) {
                throw a;
            }
            lastError = e;
            if (at >= 0) {
                observations.add(observation(at, null, e));
            }
            if (expect == null || !expect.containsKey("error")) {
                throw e;
            }
            String d = errorMismatch((Map<String, Object>) expect.get("error"), e);
            if (d != null) {
                throw new AssertionError(where + " (" + op.get("name") + "): " + d, e);
            }
            return;
        }
        if (at >= 0) {
            observations.add(observation(at, observed((String) op.get("name"), result), null));
        }
        if (op.get("saveAs") instanceof String name) {
            saved.put(name, result);
        }
        if (expect == null) {
            return;
        }
        if (expect.containsKey("error")) {
            throw new AssertionError(where + " (" + op.get("name")
                    + "): expected an error, got " + ConformanceValues.describe(result));
        }
        Object want = v(expect.get("result"));
        String d = ConformanceValues.mismatch(want, result,
                "subset".equals(op.get("match")), !Boolean.FALSE.equals(op.get("ordered")),
                Boolean.TRUE.equals(op.get("fieldOrder")));
        if (d != null) {
            throw new AssertionError(where + " (" + op.get("name") + "): " + d);
        }
    }

    /**
     * README §6: session tokens are volatile (only their presence is kept); {@code
     * listDatabaseNames} keeps the databases of this file only (other files and runners share
     * the server), with {@code ${database}} written as {@code <database>}.
     */
    private Object observed(String name, Object result) {
        if ("causalityToken".equals(name) && result != null) {
            return "<volatile>";
        }
        if ("listDatabaseNames".equals(name) && result instanceof List<?> names) {
            List<String> own = new ArrayList<>();
            for (Object n : names) {
                if (n instanceof String s && s.startsWith(database)) {
                    own.add("<database>" + s.substring(database.length()));
                }
            }
            return own;
        }
        return result;
    }

    private static Map<String, Object> observation(int at, Object result, Throwable e) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("op", at);
        if (e == null) {
            o.put("result", result);
        } else {
            Map<String, Object> err = new LinkedHashMap<>();
            if (e instanceof RustegonException r) {
                err.put("code", r.code());
                err.put("retryable", r.isRetryable());
            }
            err.put("exception", classId(e));
            o.put("error", err);
        }
        return o;
    }

    /** The most specific errors-map.yaml class id of {@code e}. */
    static String classId(Throwable e) {
        if (e instanceof ApplicationError) {
            return "ApplicationError";
        }
        for (Map.Entry<String, Class<?>> c : CLASSES.entrySet()) {
            if (c.getValue().isInstance(e)) {
                return c.getKey();
            }
        }
        return e.getClass().getSimpleName();
    }

    /** {@code null} when {@code e} satisfies the expected error, else the difference. */
    static String errorMismatch(Map<String, Object> want, Throwable e) {
        if (Boolean.TRUE.equals(want.get("applicationError"))) {
            return e instanceof ApplicationError ? null
                    : "expected the application error, got " + e;
        }
        if (want.get("exception") instanceof String id) {
            Class<?> cls = CLASSES.get(id);
            if (cls == null) {
                return "unknown exception class id " + id;
            }
            if (!cls.isInstance(e)) {
                return "expected " + id + ", got " + e;
            }
        }
        boolean rustegon = e instanceof RustegonException;
        RustegonException r = rustegon ? (RustegonException) e : null;
        if (want.get("code") instanceof Number code && (!rustegon || r.code() != code.intValue())) {
            return "expected code " + code + ", got " + e;
        }
        if (want.get("name") instanceof String name && (!rustegon || !name.equals(r.name()))) {
            return "expected name " + name + ", got " + e;
        }
        if (want.get("retryable") instanceof Boolean b && (!rustegon || r.isRetryable() != b)) {
            return "expected retryable=" + b + ", got " + e;
        }
        if (want.get("committed") instanceof Boolean b
                && (!rustegon || !r.committed().equals(Optional.of(b)))) {
            return "expected committed=" + b + ", got " + e;
        }
        return null;
    }

    // ------------------------------------------------------------------ dispatch

    @SuppressWarnings("unchecked")
    private Object invoke(Map<String, Object> op) throws Exception {
        String object = (String) op.get("object");
        String name = (String) op.get("name");
        Map<String, Object> args = op.get("args") == null ? Map.of()
                : (Map<String, Object>) op.get("args");
        Object target = switch (object) {
            case "runner" -> null;
            case "client" -> client;
            case "database" -> client.database(database);
            case "collection" -> client;
            case "transaction" -> transactions.peek();
            default -> {
                if (!saved.containsKey(object)) {
                    throw new AssertionError("unknown object " + object);
                }
                yield saved.get(object);
            }
        };
        if (object.equals("runner")) {
            return env.runner(name, args, this);
        }
        if (target instanceof RustegonClient c && (object.equals("collection")
                || op.containsKey("collection"))) {
            RustegonCollection<RDocument> coll = c.database(database).collection(
                    (String) op.getOrDefault("collection", defaultCollection));
            if (op.get("session") instanceof String s) {
                coll = coll.withSession((ClientSession) saved.get(s));
            }
            return collectionOp(coll, name, args, op);
        }
        if (target instanceof Transaction t && op.containsKey("collection")) {
            return collectionOp(t.collection(database + "." + op.get("collection")), name, args,
                    op);
        }
        return switch (target) {
            case RustegonClient c -> clientOp(c, name, args);
            case RustegonDatabase d -> databaseOp(d, name, args);
            case Transaction t -> transactionOp(t, name, args);
            case Cursor<?> cur -> switch (name) {
                case "next" -> cur.hasNext() ? cur.next() : null;
                case "close" -> {
                    cur.close();
                    yield null;
                }
                default -> throw new AssertionError("cursor." + name);
            };
            case ClientSession s -> switch (name) {
                case "causalityToken" -> s.causalityToken().orElse(null);
                case "close" -> {
                    s.close();
                    yield null;
                }
                default -> throw new AssertionError("session." + name);
            };
            case null -> throw new AssertionError("no object " + object);
            default -> throw new AssertionError("cannot call " + name + " on " + target);
        };
    }

    @SuppressWarnings("unchecked")
    private Object clientOp(RustegonClient c, String name, Map<String, Object> args)
            throws Exception {
        switch (name) {
            case "open" -> {
                RustegonClient opened = env.open(args, this);
                try {
                    opened.serverInfo(); // creating a client is lazy: log in now
                } catch (RuntimeException e) {
                    opened.close();
                    throw e;
                }
                this.opened.add(opened);
                return opened;
            }
            case "openFromConnectionString" -> {
                RustegonClient opened = RustegonClient.create(env.substitute(
                        (String) args.get("uri")));
                try {
                    opened.serverInfo();
                } catch (RuntimeException e) {
                    opened.close();
                    throw e;
                }
                this.opened.add(opened);
                return opened;
            }
            case "getServerInfo" -> {
                ServerInfo i = c.serverInfo();
                return doc("serverVersion", i.serverVersion(), "protocolVersion",
                        i.protocolVersion(), "features", new ArrayList<Object>(i.features()));
            }
            case "listDatabaseNames" -> {
                return new ArrayList<Object>(c.listDatabaseNames());
            }
            case "createDatabase" -> {
                return doc("created", c.createDatabase(str(args, "name"),
                        new CreateDatabaseOptions(Boolean.TRUE.equals(args.get("ifNotExists")))));
            }
            case "dropDatabase" -> {
                return doc("dropped", c.dropDatabase(str(args, "name"),
                        new DropOptions(Boolean.TRUE.equals(args.get("ifExists")))));
            }
            case "startSession" -> {
                ClientSession s = c.startSession(new SessionOptions(
                        !Boolean.FALSE.equals(args.get("causalConsistency"))));
                opened.add(s);
                return s;
            }
            case "beginTransaction" -> {
                Transaction t = c.beginTransaction(txnOptions(args));
                opened.add(t);
                return t;
            }
            case "withTransaction" -> {
                List<Map<String, Object>> callback = (List<Map<String, Object>>) args.get(
                        "callback");
                return c.withTransaction(txnOptions(args), txn -> {
                    transactions.push(txn);
                    try {
                        for (Map<String, Object> step : callback) {
                            run(step);
                        }
                    } catch (RuntimeException e) {
                        throw e;
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    } finally {
                        transactions.pop();
                    }
                    return null;
                });
            }
            case "manualTransaction" -> {
                try (Transaction txn = c.beginTransaction(txnOptions(args))) {
                    transactions.push(txn);
                    try {
                        for (Map<String, Object> step : (List<Map<String, Object>>) args.get(
                                "steps")) {
                            run(step);
                        }
                    } finally {
                        transactions.pop();
                    }
                }
                return null;
            }
            case "changePassword" -> {
                c.changePassword(str(args, "currentPassword").toCharArray(),
                        str(args, "newPassword").toCharArray());
                return null;
            }
            case "close" -> {
                c.close();
                return null;
            }
            default -> throw new AssertionError("client." + name);
        }
    }

    @SuppressWarnings("unchecked")
    private TransactionOptions txnOptions(Map<String, Object> args) {
        TransactionOptions o = TransactionOptions.defaults();
        Map<String, Object> m = (Map<String, Object>) args.get("options");
        if (m == null) {
            return o;
        }
        if (m.get("isolation") instanceof String iso) {
            o = o.isolation(IsolationLevel.valueOf(iso.toUpperCase(Locale.ROOT)));
        }
        if (Boolean.TRUE.equals(m.get("readOnly"))) {
            o = o.readOnly(true);
        }
        if (m.get("maxRetryTimeMs") instanceof Number n) {
            o = o.maxRetryTime(Duration.ofMillis(n.longValue()));
        }
        return o;
    }

    @SuppressWarnings("unchecked")
    private Object databaseOp(RustegonDatabase d, String name, Map<String, Object> args) {
        return switch (name) {
            case "query" -> rows(d.query(env.substitute(str(args, "rgql")), params(args),
                    new QueryOptions(args.get("batchSize") instanceof Number n ? n.intValue()
                            : null), RDocument.class));
            case "createCollection" -> {
                CreateCollectionOptions o = new CreateCollectionOptions(
                        Boolean.TRUE.equals(args.get("ifNotExists")), null);
                if (args.get("validator") instanceof Map<?, ?> vm) {
                    o = o.withValidator(validator((Map<String, Object>) vm));
                }
                yield doc("created", d.createCollection(str(args, "name"), o));
            }
            case "dropCollection" -> doc("dropped", d.dropCollection(str(args, "name"),
                    new DropOptions(Boolean.TRUE.equals(args.get("ifExists")))));
            case "listCollectionNames" -> new ArrayList<Object>(d.listCollectionNames());
            default -> throw new AssertionError("database." + name);
        };
    }

    static Validator validator(Map<String, Object> m) {
        return new Validator(ConformanceValues.json(m.get("jsonSchema")),
                m.get("level") instanceof String l
                        ? Validator.Level.valueOf(l.toUpperCase(Locale.ROOT)) : null,
                m.get("action") instanceof String a
                        ? Validator.Action.valueOf(a.toUpperCase(Locale.ROOT)) : null);
    }

    private Object transactionOp(Transaction t, String name, Map<String, Object> args) {
        switch (name) {
            case "query" -> {
                return rows(t.query(env.substitute(str(args, "rgql")), params(args),
                        RDocument.class));
            }
            case "commit" -> t.commit();
            case "rollback" -> t.rollback();
            case "close" -> t.close();
            case "resolve" -> {
                return t.resolve().name().toLowerCase(Locale.ROOT);
            }
            default -> throw new AssertionError("transaction." + name);
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Params params(Map<String, Object> args) {
        Params p = Params.empty();
        if (args.get("params") instanceof Map<?, ?> m) {
            for (Map.Entry<String, Object> e : ((Map<String, Object>) m).entrySet()) {
                p = p.and(e.getKey(), v(e.getValue()));
            }
        }
        return p;
    }

    private static List<Object> rows(Cursor<RDocument> c) {
        List<Object> out = new ArrayList<>();
        try (c) {
            c.forEachRemaining(out::add);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private Object collectionOp(RustegonCollection<RDocument> c, String name,
            Map<String, Object> args, Map<String, Object> op) {
        Map<String, Object> options = args.get("options") == null ? Map.of()
                : (Map<String, Object>) args.get("options");
        String ifRev = options.get("ifRev") == null ? null : (String) v(options.get("ifRev"));
        return switch (name) {
            case "insertOne" -> doc("insertedId", c.insertOne((RDocument) v(args.get("document")))
                    .insertedId());
            case "insertMany" -> {
                List<RDocument> docs = new ArrayList<>();
                for (Object d : (List<Object>) args.get("documents")) {
                    docs.add((RDocument) v(d));
                }
                yield doc("insertedIds", c.insertMany(docs).insertedIds());
            }
            case "findById" -> c.findById(v(args.get("id"))).orElse(null);
            case "find" -> find(c, args, (String) op.getOrDefault("then", "toList"));
            case "updateOne" -> updateResult(c.updateOne(Dsl.filter(args.get("filter"), this::v),
                    Dsl.update(args.get("update"), this::v), new UpdateOptions(ifRev)));
            case "updateMany" -> updateResult(c.updateMany(Dsl.filter(args.get("filter"),
                    this::v), Dsl.update(args.get("update"), this::v), new UpdateOptions(ifRev)));
            case "replaceOne" -> updateResult(c.replaceOne(Dsl.filter(args.get("filter"),
                    this::v), (RDocument) v(args.get("replacement")), new ReplaceOptions(
                    Boolean.TRUE.equals(options.get("upsert")), ifRev)));
            case "deleteOne" -> doc("deletedCount", c.deleteOne(Dsl.filter(args.get("filter"),
                    this::v), new DeleteOptions(ifRev)).deletedCount());
            case "deleteMany" -> doc("deletedCount", c.deleteMany(Dsl.filter(args.get("filter"),
                    this::v), new DeleteOptions(ifRev)).deletedCount());
            case "bulkWrite" -> bulk(c, args);
            case "createIndex" -> {
                List<IndexKey> keys = new ArrayList<>();
                for (Map<String, Object> k : (List<Map<String, Object>>) args.get("keys")) {
                    keys.add(new IndexKey((String) k.get("path"),
                            Boolean.TRUE.equals(k.get("descending"))));
                }
                IndexInfo i = c.createIndex(str(args, "name"), new IndexKeys(keys),
                        new CreateIndexOptions(Boolean.TRUE.equals(args.get("unique"))));
                yield doc("name", i.name(), "state", i.state().name().toLowerCase(Locale.ROOT));
            }
            case "dropIndex" -> doc("dropped", c.dropIndex(str(args, "name"),
                    new DropOptions(Boolean.TRUE.equals(args.get("ifExists")))));
            case "listIndexes" -> {
                List<Object> out = new ArrayList<>();
                for (IndexInfo i : c.listIndexes()) {
                    List<Object> keys = new ArrayList<>();
                    for (IndexKey k : i.keys()) {
                        keys.add(doc("path", k.path(), "descending", k.descending()));
                    }
                    out.add(doc("name", i.name(), "keys", keys, "unique", i.unique(), "state",
                            i.state().name().toLowerCase(Locale.ROOT)));
                }
                yield out;
            }
            default -> throw new AssertionError("collection." + name);
        };
    }

    private Object find(RustegonCollection<RDocument> c, Map<String, Object> args, String then) {
        FindIterable<RDocument> f = c.find(Dsl.filter(args.getOrDefault("filter", Map.of()),
                this::v));
        if (args.get("sort") != null) {
            f.sort(Dsl.sort(args.get("sort")));
        }
        if (args.get("limit") instanceof Number n) {
            f.limit(n.intValue());
        }
        if (args.get("skip") instanceof Number n) {
            f.skip(n.intValue());
        }
        if (args.get("projection") != null) {
            f.projection(Dsl.projection(args.get("projection")));
        }
        if (args.get("batchSize") instanceof Number n) {
            f.batchSize(n.intValue());
        }
        return switch (then) {
            case "first" -> f.first().orElse(null);
            case "cursor" -> {
                Cursor<RDocument> cur = f.cursor();
                opened.add(cur);
                yield cur;
            }
            default -> new ArrayList<Object>(f.toList());
        };
    }

    @SuppressWarnings("unchecked")
    private Object bulk(RustegonCollection<RDocument> c, Map<String, Object> args) {
        List<BulkOperation<RDocument>> ops = new ArrayList<>();
        for (Map<String, Object> o : (List<Map<String, Object>>) args.get("operations")) {
            String kind = o.keySet().iterator().next();
            Map<String, Object> a = (Map<String, Object>) o.get(kind);
            BulkOperation<RDocument> b = switch (kind) {
                case "insert" -> BulkOperation.insert((RDocument) v(a.get("document")));
                case "replace" -> BulkOperation.replace(v(a.get("id")),
                        (RDocument) v(a.get("document")));
                case "update" -> BulkOperation.update(v(a.get("id")), Dsl.update(a.get("update"),
                        this::v));
                case "upsert" -> BulkOperation.upsert((RDocument) v(a.get("document")));
                case "delete" -> BulkOperation.delete(v(a.get("id")));
                default -> throw new AssertionError("bulk " + kind);
            };
            if (a.get("ifRev") != null) {
                b = b.ifRev((String) v(a.get("ifRev")));
            }
            ops.add(b);
        }
        BulkWriteResult r = c.bulkWrite(ops, new BulkWriteOptions(!Boolean.FALSE.equals(
                args.get("ordered"))));
        List<Object> errors = new ArrayList<>();
        for (BulkWriteError e : r.errors()) {
            errors.add(doc("index", (long) e.index(), "code", (long) e.error().code()));
        }
        return doc("insertedCount", r.insertedCount(), "matchedCount", r.matchedCount(),
                "modifiedCount", r.modifiedCount(), "deletedCount", r.deletedCount(), "errors",
                errors);
    }

    private static RDocument updateResult(UpdateResult r) {
        RDocument d = doc("matchedCount", r.matchedCount(), "modifiedCount", r.modifiedCount());
        if (r.upsertedId() != null) {
            d.put("upsertedId", r.upsertedId());
        }
        return d;
    }

    static RDocument doc(Object... kv) {
        RDocument d = new RDocument();
        for (int i = 0; i < kv.length; i += 2) {
            d.put((String) kv[i], kv[i + 1]);
        }
        return d;
    }

    private String str(Map<String, Object> args, String key) {
        return env.substitute((String) args.get(key));
    }

    Throwable lastError() {
        return lastError;
    }
}
