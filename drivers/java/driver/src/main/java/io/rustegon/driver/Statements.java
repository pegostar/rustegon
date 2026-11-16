// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.internal.proto.AstDelete;
import io.rustegon.driver.internal.proto.AstFromClause;
import io.rustegon.driver.internal.proto.AstOptionItem;
import io.rustegon.driver.internal.proto.AstQualifiedName;
import io.rustegon.driver.internal.proto.AstQuery;
import io.rustegon.driver.internal.proto.AstSource;
import io.rustegon.driver.internal.proto.AstStatement;
import io.rustegon.driver.internal.proto.AstUpdate;

/**
 * The statements of collection operations with a non-id filter (PD-070 rules 4–6,
 * {@code drivers/conformance/ast/statements.json}):
 *
 * <ul>
 *   <li>{@code find} = {@code FROM c [WHERE f] [SELECT projection] [ORDER BY sort] [LIMIT n]
 *       [OFFSET m]};
 *   <li>one-document writes use RGQL's single-row form {@code … LIMIT 1}: documents are visited
 *       in {@code _id} order, so the matching document with the lowest {@code _id} is written;
 *   <li>a write with the empty filter adds {@code OPTIONS (allow_full_scan_write = true)},
 *       without which the server refuses it (RGN-1013). User RGQL text is never rewritten.
 * </ul>
 */
final class Statements {
    private static final String FULL_SCAN_WRITE = "allow_full_scan_write";

    private Statements() {}

    private static AstQualifiedName name(String collection) {
        return AstQualifiedName.newBuilder().setName(collection).build();
    }

    private static AstOptionItem fullScanWrite() {
        return AstOptionItem.newBuilder().setName(FULL_SCAN_WRITE)
                .setValue(Ast.boolLiteral(true)).build();
    }

    static AstStatement find(String collection, Filter filter, Sort sort, Projection projection,
            Long limit, Long skip, Ast.ParamSink filterParams) {
        AstQuery.Builder q = AstQuery.newBuilder().setFrom(AstFromClause.newBuilder()
                .setSource(AstSource.newBuilder().setCollection(name(collection))));
        if (!filter.isEmpty()) {
            q.setWhere(filter.toAst(filterParams));
        }
        if (projection != null) {
            q.setSelect(projection.toAst());
        }
        if (sort != null) {
            q.addAllOrderBy(sort.toAst());
        }
        if (limit != null) {
            q.setLimit(Ast.intLiteral(limit));
        }
        if (skip != null) {
            q.setOffset(Ast.intLiteral(skip));
        }
        return AstStatement.newBuilder().setQuery(q).build();
    }

    static AstStatement update(String collection, Filter filter, Update update, boolean one,
            Ast.ParamSink filterParams, Ast.ParamSink updateParams) {
        AstUpdate.Builder u = AstUpdate.newBuilder().setTarget(name(collection))
                .addAllOps(update.toAst(updateParams));
        if (filter.isEmpty()) {
            u.addOptions(fullScanWrite());
        } else {
            u.setWhere(filter.toAst(filterParams));
        }
        if (one) {
            u.setLimit(Ast.intLiteral(1));
        }
        return AstStatement.newBuilder().setUpdate(u).build();
    }

    static AstStatement delete(String collection, Filter filter, boolean one,
            Ast.ParamSink filterParams) {
        AstDelete.Builder d = AstDelete.newBuilder().setTarget(name(collection));
        if (filter.isEmpty()) {
            d.addOptions(fullScanWrite());
        } else {
            d.setWhere(filter.toAst(filterParams));
        }
        if (one) {
            d.setLimit(Ast.intLiteral(1));
        }
        return AstStatement.newBuilder().setDelete(d).build();
    }
}
