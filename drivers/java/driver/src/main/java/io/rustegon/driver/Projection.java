// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import io.rustegon.driver.internal.proto.AstExprProjection;
import io.rustegon.driver.internal.proto.AstPathProjection;
import io.rustegon.driver.internal.proto.AstProjection;
import io.rustegon.driver.internal.proto.AstSelect;
import io.rustegon.driver.internal.proto.AstSelectItems;
import java.util.List;

/**
 * A projection, built with {@link Projections} (query-language.md §4.3 "Projection"): an
 * include list returns only the named fields (each named after its last segment; {@code _id} is
 * not added implicitly), an exclude list removes them. Immutable.
 */
public final class Projection {
    private final boolean exclude;
    private final List<String> paths;

    Projection(boolean exclude, List<String> paths) {
        for (String p : paths) {
            Ast.path(p);
        }
        this.exclude = exclude;
        this.paths = List.copyOf(paths);
    }

    AstSelect toAst() {
        AstSelectItems.Builder items = AstSelectItems.newBuilder();
        for (String p : paths) {
            items.addItems(exclude
                    ? AstProjection.newBuilder().setExclude(AstPathProjection.newBuilder()
                            .setPath(Ast.path(p)))
                    : AstProjection.newBuilder().setExpr(AstExprProjection.newBuilder()
                            .setExpr(Ast.pathExpr(p))));
        }
        return AstSelect.newBuilder().setItems(items).build();
    }

    @Override
    public String toString() {
        return (exclude ? "Exclude" : "Include") + paths;
    }
}
