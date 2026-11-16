// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import com.google.protobuf.ByteString;
import io.rustegon.driver.internal.ErrorMapper;
import io.rustegon.driver.internal.proto.AstExpr;
import io.rustegon.driver.internal.proto.AstLiteral;
import io.rustegon.driver.internal.proto.AstParam;
import io.rustegon.driver.internal.proto.AstPath;
import io.rustegon.driver.internal.proto.AstPathExpr;
import io.rustegon.driver.internal.proto.AstSegment;
import io.rustegon.driver.internal.proto.Value;
import io.rustegon.driver.rdoc.RDocException;
import io.rustegon.driver.rdoc.RDocReader;
import io.rustegon.driver.rdoc.RDocWriter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Small constructors of the structured query AST ({@code query_ast.proto}) shared by the
 * builders (PD-070): field paths become {@code AstPath} segments, never text, and every user
 * value becomes a named parameter.
 */
final class Ast {
    private Ast() {}

    /**
     * Allocates parameter names {@code <prefix>0, <prefix>1, …} in the order values are added
     * (PD-070 rule 1: depth-first, left-to-right) and collects their RDoc value encodings.
     */
    static final class ParamSink {
        private final String prefix;
        private final Map<String, Value> params;
        private int next;

        /** {@code params} may be shared by an {@code f} and a {@code u} sink. */
        ParamSink(String prefix, Map<String, Value> params) {
            this.prefix = prefix;
            this.params = params;
        }

        /** A fresh sink with its own map. */
        static ParamSink of(String prefix) {
            return new ParamSink(prefix, new LinkedHashMap<>());
        }

        AstExpr add(Object v) {
            String name = prefix + next++;
            params.put(name, value(v));
            return param(name);
        }

        Map<String, Value> params() {
            return params;
        }
    }

    /**
     * A dotted path: {@code a.b.0.c}; an all-digit segment after the first is an array
     * position (README §4).
     */
    static AstPath path(String dotted) {
        if (dotted == null || dotted.isEmpty()) {
            throw new IllegalArgumentException("a field path must not be empty");
        }
        AstPath.Builder b = AstPath.newBuilder();
        String[] parts = dotted.split("\\.", -1);
        for (int i = 0; i < parts.length; i++) {
            String s = parts[i];
            if (s.isEmpty()) {
                throw new IllegalArgumentException("empty segment in the field path " + dotted);
            }
            if (i > 0 && s.chars().allMatch(c -> c >= '0' && c <= '9') && s.length() <= 9) {
                b.addSegments(AstSegment.newBuilder().setPosition(Integer.parseInt(s)));
            } else {
                b.addSegments(AstSegment.newBuilder().setField(s));
            }
        }
        return b.build();
    }

    static AstExpr pathExpr(String dotted) {
        return AstExpr.newBuilder().setPath(AstPathExpr.newBuilder().setPath(path(dotted)))
                .build();
    }

    static AstExpr param(String name) {
        return AstExpr.newBuilder().setParam(AstParam.newBuilder().setName(name)).build();
    }

    static AstExpr intLiteral(long v) {
        return AstExpr.newBuilder().setLiteral(AstLiteral.newBuilder().setIntValue(v)).build();
    }

    static AstExpr boolLiteral(boolean v) {
        return AstExpr.newBuilder().setLiteral(AstLiteral.newBuilder().setBoolValue(v)).build();
    }

    /**
     * The RDoc value encoding of a parameter or id; a value the codec refuses is the client
     * error of its code (RGN-1001/1002/1003/1004/1040), like a server rejection.
     */
    static Value value(Object v) {
        try {
            return Value.newBuilder().setRdocValue(ByteString.copyFrom(RDocWriter.encodeValue(v)))
                    .build();
        } catch (RDocException e) {
            throw ErrorMapper.local(e.code(), e.getMessage(), e);
        }
    }

    /** The RDoc document encoding of a document; codec errors as in {@link #value}. */
    static ByteString document(Map<?, ?> doc) {
        try {
            return ByteString.copyFrom(RDocWriter.encode(doc));
        } catch (RDocException e) {
            throw ErrorMapper.local(e.code(), e.getMessage(), e);
        }
    }

    /** A value of a response. */
    static Object decode(Value v) {
        return RDocReader.decodeValue(v.getRdocValue().toByteArray());
    }
}
