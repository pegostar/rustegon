// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import com.google.protobuf.Message;
import io.rustegon.driver.internal.proto.AstStatement;
import io.rustegon.driver.internal.proto.AstUpdateOp;
import io.rustegon.driver.internal.proto.Value;
import io.rustegon.driver.rdoc.RDocument;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The runner operation {@code checkAstVectors} (drivers/conformance/README.md §4, PD-070): each
 * case's builder DSL is translated into builder calls, and the protobuf JSON of the resulting
 * AST and the RDoc value encoding of every parameter must equal the golden vectors written by
 * {@code crates/rustegon-server/tests/driver_ast.rs}.
 */
final class AstVectors {
    private AstVectors() {}

    /** Checks every case of {@code file}; the failures, one line each. */
    @SuppressWarnings("unchecked")
    static List<String> check(Path file) throws Exception {
        Map<String, Object> root = ConformanceValues.load(file);
        String collection = (String) root.get("collection");
        Function<Object, Object> v = y -> ConformanceValues.value(y, r -> null, s -> s);
        List<String> failures = new ArrayList<>();
        String kind = file.getFileName().toString();
        for (Map<String, Object> c : (List<Map<String, Object>>) root.get("cases")) {
            try {
                Map<String, Value> params = new LinkedHashMap<>();
                List<String> diffs = new ArrayList<>();
                switch (kind) {
                    case "filters.json" -> {
                        Filter f = Dsl.filter(c.get("filter"), v);
                        Ast.ParamSink fp = new Ast.ParamSink("f", params);
                        AstStatement st = Statements.find(collection, f, null, null, null, null,
                                fp);
                        same(c.get("statement"), st, "statement", diffs);
                        same(c.get("where"), st.getQuery().getWhere(), "where", diffs);
                    }
                    case "updates.json" -> {
                        List<AstUpdateOp> ops = Dsl.update(c.get("update"), v).toAst(
                                new Ast.ParamSink("u", params));
                        List<Object> trees = new ArrayList<>();
                        for (AstUpdateOp op : ops) {
                            trees.add(ProtoJson.tree(op));
                        }
                        if (!ProtoJson.normalise(c.get("operations")).equals(trees)) {
                            diffs.add("operations " + trees);
                        }
                    }
                    case "statements.json" -> same(c.get("statement"), statement(collection,
                            (String) c.get("op"), (Map<String, Object>) c.get("args"), v, params),
                            "statement", diffs);
                    default -> throw new IllegalArgumentException("unknown AST file " + kind);
                }
                Map<String, String> want = new LinkedHashMap<>();
                ((Map<String, Map<String, Object>>) c.get("params")).forEach(
                        (k, p) -> want.put(k, (String) p.get("hex")));
                Map<String, String> got = new LinkedHashMap<>();
                params.forEach((k, p) -> got.put(k, HexFormat.of().formatHex(
                        p.getRdocValue().toByteArray())));
                if (!want.equals(got)) {
                    diffs.add("params " + got + ", expected " + want);
                }
                if (!diffs.isEmpty()) {
                    failures.add(c.get("name") + ": " + String.join("; ", diffs));
                }
            } catch (RuntimeException e) {
                failures.add(c.get("name") + ": " + e);
            }
        }
        return failures;
    }

    private static void same(Object expected, Message actual, String what, List<String> diffs) {
        Map<String, Object> got = ProtoJson.tree(actual);
        if (!ProtoJson.normalise(expected).equals(got)) {
            diffs.add(what + " " + got);
        }
    }

    @SuppressWarnings("unchecked")
    private static AstStatement statement(String coll, String op, Map<String, Object> args,
            Function<Object, Object> v, Map<String, Value> params) {
        Filter f = Dsl.filter(args.get("filter"), v);
        Ast.ParamSink fp = new Ast.ParamSink("f", params);
        Ast.ParamSink up = new Ast.ParamSink("u", params);
        return switch (op) {
            case "find" -> Statements.find(coll, f,
                    args.get("sort") == null ? null : Dsl.sort(args.get("sort")),
                    args.get("projection") == null ? null : Dsl.projection(args.get("projection")),
                    args.get("limit") instanceof Number n ? n.longValue() : null,
                    args.get("skip") instanceof Number n ? n.longValue() : null, fp);
            case "updateOne", "updateMany" -> Statements.update(coll, f, Dsl.update(
                    args.get("update"), v), op.equals("updateOne"), fp, up);
            case "replaceOne" -> Statements.update(coll, f, Update.replaceWith(
                    (RDocument) v.apply(args.get("replacement"))), true, fp, up);
            case "deleteOne", "deleteMany" -> Statements.delete(coll, f, op.equals("deleteOne"),
                    fp);
            default -> throw new IllegalArgumentException("unknown statement op " + op);
        };
    }
}
