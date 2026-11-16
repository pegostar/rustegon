// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Message;
import io.rustegon.driver.internal.proto.Document;
import io.rustegon.driver.internal.proto.Value;
import io.rustegon.driver.rdoc.RDocWriter;
import io.rustegon.driver.rdoc.RDocument;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The protobuf JSON mapping by descriptor, for tests (protobuf-java-util's {@code JsonFormat} is
 * not a dependency of the driver): messages to JSON trees (lowerCamelCase names, enum names,
 * 64-bit integers as strings, defaults omitted — what {@code JsonFormat.printer()} prints, the
 * form of {@code drivers/conformance/ast/*.json}), and JSON trees to messages for the fake
 * server, with {@code Document} / {@code Value} fields given as extended JSON (retry.yaml).
 */
final class ProtoJson {
    private ProtoJson() {}

    /** A message as a JSON tree (maps, lists, strings, longs, doubles, booleans). */
    static Map<String, Object> tree(Message m) {
        Map<String, Object> out = new LinkedHashMap<>();
        m.getAllFields().forEach((f, v) -> {
            if (f.isRepeated()) {
                List<Object> l = new ArrayList<>();
                for (Object e : (List<?>) v) {
                    l.add(scalar(f, e));
                }
                out.put(f.getJsonName(), l);
            } else {
                out.put(f.getJsonName(), scalar(f, v));
            }
        });
        return out;
    }

    private static Object scalar(FieldDescriptor f, Object v) {
        return switch (f.getJavaType()) {
            case MESSAGE -> tree((Message) v);
            case ENUM -> ((com.google.protobuf.Descriptors.EnumValueDescriptor) v).getName();
            case LONG -> String.valueOf(v);
            case INT -> ((Integer) v).longValue();
            case BYTE_STRING -> Base64.getEncoder().encodeToString(((ByteString) v).toByteArray());
            default -> v;
        };
    }

    /** A parsed JSON tree with its numbers normalised (Integer to Long) for comparison. */
    static Object normalise(Object y) {
        if (y instanceof Integer i) {
            return i.longValue();
        }
        if (y instanceof List<?> l) {
            List<Object> out = new ArrayList<>();
            for (Object e : l) {
                out.add(normalise(e));
            }
            return out;
        }
        if (y instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            m.forEach((k, v) -> out.put(String.valueOf(k), normalise(v)));
            return out;
        }
        return y;
    }

    /**
     * Fills {@code b} from a JSON tree; {@code Document} and {@code Value} fields are extended
     * JSON turned into driver values by {@code toValue}.
     */
    @SuppressWarnings("unchecked")
    static <B extends Message.Builder> B fill(B b, Map<String, Object> json,
            Function<Object, Object> toValue) {
        var d = b.getDescriptorForType();
        for (Map.Entry<String, Object> e : json.entrySet()) {
            FieldDescriptor f = null;
            for (FieldDescriptor x : d.getFields()) {
                if (x.getJsonName().equals(e.getKey()) || x.getName().equals(e.getKey())) {
                    f = x;
                }
            }
            if (f == null) {
                throw new IllegalArgumentException("no field " + e.getKey() + " in "
                        + d.getFullName());
            }
            if (f.isRepeated()) {
                for (Object x : (List<Object>) e.getValue()) {
                    b.addRepeatedField(f, convert(b, f, x, toValue));
                }
            } else {
                b.setField(f, convert(b, f, e.getValue(), toValue));
            }
        }
        return b;
    }

    @SuppressWarnings("unchecked")
    private static Object convert(Message.Builder parent, FieldDescriptor f, Object v,
            Function<Object, Object> toValue) {
        return switch (f.getJavaType()) {
            case MESSAGE -> {
                String type = f.getMessageType().getFullName();
                if (type.equals("rustegon.v1.Document")) {
                    yield Document.newBuilder().setRdoc(ByteString.copyFrom(RDocWriter.encode(
                            (RDocument) toValue.apply(v)))).build();
                }
                if (type.equals("rustegon.v1.Value")) {
                    yield Value.newBuilder().setRdocValue(ByteString.copyFrom(
                            RDocWriter.encodeValue(toValue.apply(v)))).build();
                }
                yield fill(parent.newBuilderForField(f), (Map<String, Object>) v, toValue)
                        .build();
            }
            case ENUM -> f.getEnumType().findValueByName((String) v);
            case INT -> ((Number) v).intValue();
            case LONG -> v instanceof String s ? Long.parseLong(s) : ((Number) v).longValue();
            case DOUBLE -> ((Number) v).doubleValue();
            case FLOAT -> ((Number) v).floatValue();
            case BOOLEAN -> (Boolean) v;
            case BYTE_STRING -> ByteString.copyFrom(Base64.getDecoder().decode((String) v));
            default -> String.valueOf(v);
        };
    }
}
