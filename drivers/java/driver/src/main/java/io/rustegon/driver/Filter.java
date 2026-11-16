// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.internal.proto.AstBinary;
import io.rustegon.driver.internal.proto.AstBinaryOp;
import io.rustegon.driver.internal.proto.AstElemMatch;
import io.rustegon.driver.internal.proto.AstExpr;
import io.rustegon.driver.internal.proto.AstIs;
import io.rustegon.driver.internal.proto.AstIsTest;
import io.rustegon.driver.internal.proto.AstNary;
import io.rustegon.driver.internal.proto.AstUnary;
import java.util.List;
import java.util.Objects;

/**
 * A query filter, built with {@link Filters} (PD-070). Immutable. It is translated into the
 * structured AST of {@code query_ast.proto}, never into RGQL text: values travel as parameters
 * and field names as path segments, so no value can change the query (no injection). The exact
 * output is pinned by {@code drivers/conformance/ast/filters.json}.
 */
public final class Filter {
    /** Builder operator. */
    enum Op {
        EMPTY, ID, EQ, NE, GT, GTE, LT, LTE, IN, NIN, EXISTS, IS_NULL, CONTAINS, CONTAINS_ANY,
        CONTAINS_ALL, ELEM_MATCH, LIKE, REGEX, AND, OR, NOT
    }

    static final Filter EMPTY = new Filter(Op.EMPTY, null, null, List.of());

    private final Op op;
    private final String path;
    private final Object value;
    private final List<Filter> args;

    Filter(Op op, String path, Object value, List<Filter> args) {
        this.op = op;
        this.path = path;
        this.value = value;
        this.args = args;
    }

    /**
     * This filter and {@code other} ({@code Filters.and(this, other)}).
     *
     * @param other the other filter
     * @return the conjunction
     */
    public Filter and(Filter other) {
        return Filters.and(this, other);
    }

    /**
     * This filter or {@code other} ({@code Filters.or(this, other)}).
     *
     * @param other the other filter
     * @return the disjunction
     */
    public Filter or(Filter other) {
        return Filters.or(this, other);
    }

    /** Whether this is {@link Filters#empty()} (matches every document). */
    boolean isEmpty() {
        return op == Op.EMPTY;
    }

    /** Whether this is exactly {@link Filters#id(Object)} (routed to DocumentService). */
    boolean isId() {
        return op == Op.ID;
    }

    /** The id of {@link Filters#id(Object)}. */
    Object idValue() {
        return value;
    }

    /** The AST expression; values are added to {@code params} in DSL order. */
    AstExpr toAst(Ast.ParamSink params) {
        return switch (op) {
            case EMPTY -> throw new IllegalArgumentException(
                    "the empty filter cannot be nested in another filter");
            case ID -> binary(AstBinaryOp.AST_BINARY_OP_EQ, "_id", params);
            case EQ -> binary(AstBinaryOp.AST_BINARY_OP_EQ, path, params);
            case NE -> binary(AstBinaryOp.AST_BINARY_OP_NE, path, params);
            case GT -> binary(AstBinaryOp.AST_BINARY_OP_GT, path, params);
            case GTE -> binary(AstBinaryOp.AST_BINARY_OP_GE, path, params);
            case LT -> binary(AstBinaryOp.AST_BINARY_OP_LT, path, params);
            case LTE -> binary(AstBinaryOp.AST_BINARY_OP_LE, path, params);
            case IN -> binary(AstBinaryOp.AST_BINARY_OP_IN, path, params);
            case NIN -> binary(AstBinaryOp.AST_BINARY_OP_NOT_IN, path, params);
            case CONTAINS -> binary(AstBinaryOp.AST_BINARY_OP_CONTAINS, path, params);
            case CONTAINS_ANY -> binary(AstBinaryOp.AST_BINARY_OP_CONTAINS_ANY, path, params);
            case CONTAINS_ALL -> binary(AstBinaryOp.AST_BINARY_OP_CONTAINS_ALL, path, params);
            case LIKE -> binary(AstBinaryOp.AST_BINARY_OP_LIKE, path, params);
            case REGEX -> binary(AstBinaryOp.AST_BINARY_OP_MATCHES, path, params);
            // exists(p, true) = p IS NOT MISSING; exists(p, false) = p IS MISSING.
            case EXISTS -> is(AstIsTest.AST_IS_TEST_MISSING, (Boolean) value);
            case IS_NULL -> is(AstIsTest.AST_IS_TEST_NULL, false);
            case ELEM_MATCH -> AstExpr.newBuilder().setElemMatch(AstElemMatch.newBuilder()
                    .setPath(Ast.path(path)).setPredicate(args.get(0).toAst(params))).build();
            case NOT -> AstExpr.newBuilder().setNot(AstUnary.newBuilder()
                    .setExpr(args.get(0).toAst(params))).build();
            case AND, OR -> nary(params);
        };
    }

    private AstExpr binary(AstBinaryOp binaryOp, String field, Ast.ParamSink params) {
        AstExpr left = Ast.pathExpr(field);
        return AstExpr.newBuilder().setBinary(AstBinary.newBuilder().setOp(binaryOp)
                .setLeft(left).setRight(params.add(value))).build();
    }

    private AstExpr is(AstIsTest test, boolean negated) {
        return AstExpr.newBuilder().setIs(AstIs.newBuilder().setExpr(Ast.pathExpr(path))
                .setNegated(negated).setTest(test)).build();
    }

    /**
     * n-ary {@code and}/{@code or}; nested nodes of the same kind are flattened (PD-070 rule
     * 2: the server accepts only the canonical AST), empty filters are dropped and a single
     * remaining operand stands alone.
     */
    private AstExpr nary(Ast.ParamSink params) {
        AstNary.Builder n = AstNary.newBuilder();
        for (Filter f : args) {
            if (f.isEmpty()) {
                continue;
            }
            AstExpr e = f.toAst(params);
            if (op == Op.AND && e.hasAnd()) {
                n.addAllArgs(e.getAnd().getArgsList());
            } else if (op == Op.OR && e.hasOr()) {
                n.addAllArgs(e.getOr().getArgsList());
            } else {
                n.addArgs(e);
            }
        }
        if (n.getArgsCount() == 0) {
            throw new IllegalArgumentException("and/or needs at least one non-empty filter");
        }
        if (n.getArgsCount() == 1) {
            return n.getArgs(0);
        }
        return op == Op.AND ? AstExpr.newBuilder().setAnd(n).build()
                : AstExpr.newBuilder().setOr(n).build();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Filter f && op == f.op && Objects.equals(path, f.path)
                && Objects.equals(value, f.value) && args.equals(f.args);
    }

    @Override
    public int hashCode() {
        return Objects.hash(op, path, args);
    }

    @Override
    public String toString() {
        // Values are user data: never part of the text (they could be secrets).
        return "Filter[" + op + (path == null ? "" : " " + path) + (args.isEmpty() ? ""
                : " " + args) + "]";
    }
}
