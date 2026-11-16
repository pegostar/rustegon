// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.internal.proto.AstBinary;
import io.rustegon.driver.internal.proto.AstBinaryOp;
import io.rustegon.driver.internal.proto.AstExpr;
import io.rustegon.driver.internal.proto.AstPath;
import io.rustegon.driver.internal.proto.AstPathBy;
import io.rustegon.driver.internal.proto.AstPathOnly;
import io.rustegon.driver.internal.proto.AstPathValue;
import io.rustegon.driver.internal.proto.AstPopEnd;
import io.rustegon.driver.internal.proto.AstPopOp;
import io.rustegon.driver.internal.proto.AstPullOp;
import io.rustegon.driver.internal.proto.AstPushOp;
import io.rustegon.driver.internal.proto.AstRenameOp;
import io.rustegon.driver.internal.proto.AstReplaceOp;
import io.rustegon.driver.internal.proto.AstSetItem;
import io.rustegon.driver.internal.proto.AstSetStage;
import io.rustegon.driver.internal.proto.AstUnsetStage;
import io.rustegon.driver.internal.proto.AstUpdateOp;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Update operators applied in order, all or nothing (data-model.md §2.3), built with
 * {@link Updates} and chained: {@code Updates.set("status", "shipped").inc("version", 1)}.
 * Immutable. Translated into {@code AstUpdateOp}s with parameters {@code u0, u1, …} (PD-070;
 * pinned by {@code drivers/conformance/ast/updates.json}). Two operators on overlapping paths
 * are rejected by the server (RGN-1001).
 */
public final class Update {
    /** One operator; {@code value} is the operand, or the target path of {@code rename}. */
    private record Op(String kind, String path, Object value) {}

    static final Update NONE = new Update(List.of());

    private final List<Op> ops;

    private Update(List<Op> ops) {
        this.ops = ops;
    }

    private Update with(String kind, String path, Object value) {
        List<Op> next = new ArrayList<>(ops);
        next.add(new Op(kind, path, value));
        return new Update(List.copyOf(next));
    }

    private Update path(String kind, String path, Object value) {
        return with(kind, Objects.requireNonNull(path, "path"), value);
    }

    /** {@code REPLACE WITH document}: the whole document (sole operator, replaceOne). */
    static Update replaceWith(Object document) {
        return new Update(List.of(new Op("replace", null, document)));
    }

    /**
     * Also sets {@code path} to {@code value}.
     *
     * @param path field path
     * @param value the value
     * @return the update
     */
    public Update set(String path, Object value) {
        return path("set", path, value);
    }

    /**
     * Also removes {@code path}.
     *
     * @param path field path
     * @return the update
     */
    public Update unset(String path) {
        return path("unset", path, null);
    }

    /**
     * Also adds {@code by} to the number at {@code path} (RGN-1011 for a non-number).
     *
     * @param path field path
     * @param by the increment
     * @return the update
     */
    public Update inc(String path, Object by) {
        return path("inc", path, Objects.requireNonNull(by, "by"));
    }

    /**
     * Also multiplies the number at {@code path} by {@code by}.
     *
     * @param path field path
     * @param by the factor
     * @return the update
     */
    public Update mul(String path, Object by) {
        return path("mul", path, Objects.requireNonNull(by, "by"));
    }

    /**
     * Also sets {@code path} to {@code value} if that is smaller.
     *
     * @param path field path
     * @param value the value
     * @return the update
     */
    public Update min(String path, Object value) {
        return path("min", path, value);
    }

    /**
     * Also sets {@code path} to {@code value} if that is larger.
     *
     * @param path field path
     * @param value the value
     * @return the update
     */
    public Update max(String path, Object value) {
        return path("max", path, value);
    }

    /**
     * Also appends {@code value} to the array at {@code path}.
     *
     * @param path field path
     * @param value the element
     * @return the update
     */
    public Update push(String path, Object value) {
        return path("push", path, value);
    }

    /**
     * Also appends {@code value} to the array at {@code path} unless already present.
     *
     * @param path field path
     * @param value the element
     * @return the update
     */
    public Update addToSet(String path, Object value) {
        return path("addToSet", path, value);
    }

    /**
     * Also removes every element equal to {@code value} from the array at {@code path}.
     *
     * @param path field path
     * @param value the element
     * @return the update
     */
    public Update pull(String path, Object value) {
        return path("pull", path, value);
    }

    /**
     * Also removes the first element of the array at {@code path}.
     *
     * @param path field path
     * @return the update
     */
    public Update popFirst(String path) {
        return path("popFirst", path, null);
    }

    /**
     * Also removes the last element of the array at {@code path}.
     *
     * @param path field path
     * @return the update
     */
    public Update popLast(String path) {
        return path("popLast", path, null);
    }

    /**
     * Also renames the field {@code from} to {@code to}.
     *
     * @param from current path
     * @param to new path
     * @return the update
     */
    public Update rename(String from, String to) {
        return path("rename", from, Objects.requireNonNull(to, "to"));
    }

    /**
     * Also sets {@code path} to the server's current datetime.
     *
     * @param path field path
     * @return the update
     */
    public Update currentDate(String path) {
        return path("currentDate", path, null);
    }

    /**
     * This update followed by the operators of {@code other}.
     *
     * @param other the other update
     * @return the combined update
     */
    public Update combine(Update other) {
        List<Op> next = new ArrayList<>(ops);
        next.addAll(other.ops);
        return new Update(List.copyOf(next));
    }

    boolean isEmpty() {
        return ops.isEmpty();
    }

    /** The {@code AstUpdateOp}s; operands are added to {@code params} in order. */
    List<AstUpdateOp> toAst(Ast.ParamSink params) {
        if (ops.isEmpty()) {
            throw new IllegalArgumentException("an update needs at least one operator");
        }
        List<AstUpdateOp> out = new ArrayList<>(ops.size());
        for (Op op : ops) {
            AstUpdateOp.Builder b = AstUpdateOp.newBuilder();
            AstPath p = op.path() == null ? null : Ast.path(op.path());
            switch (op.kind()) {
                case "set" -> b.setSet(AstSetStage.newBuilder().addItems(AstSetItem.newBuilder()
                        .setPath(p).setValue(params.add(op.value()))));
                case "unset" -> b.setUnset(AstUnsetStage.newBuilder().addPaths(p));
                case "inc" -> b.setInc(AstPathBy.newBuilder().setPath(p)
                        .setBy(params.add(op.value())));
                case "mul" -> b.setMul(AstPathBy.newBuilder().setPath(p)
                        .setBy(params.add(op.value())));
                case "min" -> b.setMin(pathValue(p, op, params));
                case "max" -> b.setMax(pathValue(p, op, params));
                case "addToSet" -> b.setAddToSet(pathValue(p, op, params));
                case "push" -> b.setPush(AstPushOp.newBuilder().setPath(p)
                        .setValue(params.add(op.value())));
                // PULL p WHERE <last field of p> = $u (README §4): the element is named after
                // the array field inside the predicate.
                case "pull" -> b.setPull(AstPullOp.newBuilder().setPath(p).setWhere(
                        AstExpr.newBuilder().setBinary(AstBinary.newBuilder()
                                .setOp(AstBinaryOp.AST_BINARY_OP_EQ)
                                .setLeft(Ast.pathExpr(p.getSegments(p.getSegmentsCount() - 1)
                                        .getField()))
                                .setRight(params.add(op.value())))));
                case "popFirst" -> b.setPop(AstPopOp.newBuilder().setPath(p)
                        .setEnd(AstPopEnd.AST_POP_END_FIRST));
                case "popLast" -> b.setPop(AstPopOp.newBuilder().setPath(p)
                        .setEnd(AstPopEnd.AST_POP_END_LAST));
                case "rename" -> b.setRename(AstRenameOp.newBuilder().setFrom(p)
                        .setTo(Ast.path((String) op.value())));
                case "currentDate" -> b.setCurrentDate(AstPathOnly.newBuilder().setPath(p));
                case "replace" -> b.setReplace(AstReplaceOp.newBuilder()
                        .setValue(params.add(op.value())));
                default -> throw new IllegalStateException("unknown operator " + op.kind());
            }
            out.add(b.build());
        }
        return out;
    }

    private static AstPathValue pathValue(AstPath p, Op op, Ast.ParamSink params) {
        return AstPathValue.newBuilder().setPath(p).setValue(params.add(op.value())).build();
    }

    @Override
    public String toString() {
        // Operands are user data: only operator kinds and paths are shown.
        StringBuilder s = new StringBuilder("Update[");
        for (Op op : ops) {
            s.append(op.kind()).append(op.path() == null ? "" : " " + op.path()).append(';');
        }
        return s.append(']').toString();
    }
}
