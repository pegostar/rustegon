// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.mapping;

import io.rustegon.driver.rdoc.ObjectId;
import io.rustegon.driver.rdoc.RDocument;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.RecordComponent;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

/**
 * The codec of a mapped type (java-driver.md §5): the generated {@code <Type>_RgnCodec} when the
 * {@code rustegon-processor} annotation processor produced one, otherwise one built at run time
 * from the type's record components or fields with {@code MethodHandles}. Both follow the same
 * rules and write identical documents (TC-DRV-JAVA-022).
 *
 * <p>Mapped types: records (canonical constructor), sealed interfaces / sealed abstract classes
 * ({@link RgnDiscriminator}) and concrete classes with a no-argument constructor (POJOs: their
 * non-static, non-transient fields, superclass fields first, in declaration order). Generic
 * types are not mapped. Property types: see {@link Values}; {@code Optional<E>}, {@code List<E>},
 * {@code Map<String, V>}, enums and other mapped types.
 */
public final class Mapper {
    private Mapper() {}

    private static final ClassValue<DocumentCodec<?>> CODECS = new ClassValue<>() {
        @Override
        protected DocumentCodec<?> computeValue(Class<?> type) {
            DocumentCodec<?> generated = generated(type);
            return generated != null ? generated : build(type, false);
        }
    };

    /** Run-time codecs only, nested types included (tests compare them with generated ones). */
    private static final ClassValue<DocumentCodec<?>> REFLECTIVE = new ClassValue<>() {
        @Override
        protected DocumentCodec<?> computeValue(Class<?> type) {
            return build(type, true);
        }
    };

    /**
     * The codec of {@code type} (cached).
     *
     * @param type a record, POJO or sealed type
     * @param <T> the type
     * @return the codec
     * @throws IllegalArgumentException if the type cannot be mapped (the message names the
     *     property)
     */
    @SuppressWarnings("unchecked")
    public static <T> DocumentCodec<T> codec(Class<T> type) {
        return (DocumentCodec<T>) CODECS.get(type);
    }

    /**
     * The name of the codec the annotation processor generates for {@code type}: same package,
     * nested names joined by {@code _}, suffix {@code _RgnCodec}.
     *
     * @param type the type
     * @return the binary name of the generated class
     */
    public static String generatedCodecName(Class<?> type) {
        String pkg = type.getPackageName();
        String simple = type.getName().substring(pkg.isEmpty() ? 0 : pkg.length() + 1)
                .replace('$', '_');
        return (pkg.isEmpty() ? "" : pkg + ".") + simple + "_RgnCodec";
    }

    /** The run-time ({@code MethodHandles}) codec of {@code type}, never a generated one. */
    @SuppressWarnings("unchecked")
    static <T> DocumentCodec<T> reflective(Class<T> type) {
        return (DocumentCodec<T>) REFLECTIVE.get(type);
    }

    private static DocumentCodec<?> resolve(Class<?> type, boolean reflective) {
        return reflective ? reflective(type) : codec(type);
    }

    private static DocumentCodec<?> generated(Class<?> type) {
        Class<?> cls;
        try {
            cls = Class.forName(generatedCodecName(type), true, type.getClassLoader());
        } catch (ClassNotFoundException | LinkageError e) {
            return null;
        }
        try {
            return (DocumentCodec<?>) cls.getField("INSTANCE").get(null);
        } catch (ReflectiveOperationException | ClassCastException e) {
            throw new IllegalArgumentException("cannot use " + cls.getName() + " (in a named "
                    + "module, export its package to io.rustegon.driver)", e);
        }
    }

    // ------------------------------------------------------------------ run-time mapper

    private static DocumentCodec<?> build(Class<?> type, boolean reflective) {
        if (type.getTypeParameters().length > 0) {
            throw new IllegalArgumentException(type.getName() + ": generic types are not mapped");
        }
        if (type.isSealed()) {
            return sealed(type, reflective);
        }
        if (type.isRecord()) {
            return record(type, reflective);
        }
        if (type.isInterface() || type.isEnum() || type.isArray() || type.isPrimitive()
                || Modifier.isAbstract(type.getModifiers()) || isJdk(type)) {
            throw new IllegalArgumentException(type.getName() + " is not a mappable document "
                    + "type (record, sealed type or concrete class)");
        }
        return pojo(type, reflective);
    }

    private static <T> DocumentCodec<T> record(Class<T> type, boolean reflective) {
        MethodHandles.Lookup lookup = lookup(type);
        RecordComponent[] components = type.getRecordComponents();
        ObjectCodec.Builder<T> b = ObjectCodec.builder(type);
        boolean explicitId = hasId(components);
        Class<?>[] types = new Class<?>[components.length];
        for (int i = 0; i < components.length; i++) {
            RecordComponent c = components[i];
            types[i] = c.getType();
            MethodHandle getter;
            try {
                getter = lookup.unreflect(c.getAccessor());
            } catch (IllegalAccessException e) {
                throw inaccessible(type, e);
            }
            addProperty(b, type, c, c.getName(), c.getType(), c.getGenericType(), explicitId,
                    function(getter), reflective);
        }
        MethodHandle ctor;
        try {
            ctor = lookup.unreflectConstructor(type.getDeclaredConstructor(types))
                    .asSpreader(Object[].class, components.length);
        } catch (IllegalAccessException | NoSuchMethodException e) {
            throw inaccessible(type, e);
        }
        return b.build(args -> {
            try {
                return type.cast(ctor.invoke(args));
            } catch (Throwable e) {
                throw rethrow(e);
            }
        });
    }

    private static <T> DocumentCodec<T> pojo(Class<T> type, boolean reflective) {
        List<Field> fields = new ArrayList<>();
        for (Class<?> c = type; c != Object.class; c = c.getSuperclass()) {
            List<Field> own = new ArrayList<>();
            for (Field f : c.getDeclaredFields()) {
                int m = f.getModifiers();
                if (!Modifier.isStatic(m) && !Modifier.isTransient(m) && !f.isSynthetic()) {
                    own.add(f);
                }
            }
            fields.addAll(0, own);
        }
        boolean explicitId = hasId(fields.toArray(AnnotatedElement[]::new));
        ObjectCodec.Builder<T> b = ObjectCodec.builder(type);
        List<MethodHandle> setters = new ArrayList<>();
        for (Field f : fields) {
            MethodHandles.Lookup lookup = lookup(f.getDeclaringClass());
            MethodHandle getter;
            MethodHandle setter = null;
            try {
                getter = lookup.unreflectGetter(f);
                if (!f.isAnnotationPresent(RgnIgnore.class)) {
                    if (Modifier.isFinal(f.getModifiers())) {
                        throw new IllegalArgumentException(type.getName() + "." + f.getName()
                                + ": final fields of a class are not mapped (use a record)");
                    }
                    setter = lookup.unreflectSetter(f);
                }
            } catch (IllegalAccessException e) {
                throw inaccessible(type, e);
            }
            setters.add(setter);
            addProperty(b, type, f, f.getName(), f.getType(), f.getGenericType(), explicitId,
                    function(getter), reflective);
        }
        MethodHandle ctor;
        try {
            Constructor<T> c = type.getDeclaredConstructor();
            ctor = lookup(type).unreflectConstructor(c);
        } catch (NoSuchMethodException e) {
            throw new IllegalArgumentException(type.getName() + " needs a no-argument "
                    + "constructor", e);
        } catch (IllegalAccessException e) {
            throw inaccessible(type, e);
        }
        return b.build(args -> {
            try {
                Object o = ctor.invoke();
                for (int i = 0; i < args.length; i++) {
                    MethodHandle s = setters.get(i);
                    if (s != null) {
                        s.invoke(o, args[i]);
                    }
                }
                return type.cast(o);
            } catch (Throwable e) {
                throw rethrow(e);
            }
        });
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static <T> DocumentCodec<T> sealed(Class<T> type, boolean reflective) {
        if (type.isRecord() || !(type.isInterface() || Modifier.isAbstract(type.getModifiers()))) {
            throw new IllegalArgumentException(type.getName() + ": only sealed interfaces and "
                    + "sealed abstract classes are mapped polymorphically");
        }
        RgnDiscriminator root = type.getAnnotation(RgnDiscriminator.class);
        SealedCodec.Builder<T> b = SealedCodec.builder(type, root == null ? "_type"
                : root.field());
        List<Class<?>> leaves = new ArrayList<>();
        collectLeaves(type, leaves);
        for (Class<?> leaf : leaves) {
            RgnDiscriminator d = leaf.getAnnotation(RgnDiscriminator.class);
            String tag = d == null || d.value().isEmpty() ? leaf.getSimpleName() : d.value();
            b.subtype(tag, (Class) leaf, (DocumentCodec) resolve(leaf, reflective));
        }
        return b.build();
    }

    private static void collectLeaves(Class<?> type, List<Class<?>> out) {
        for (Class<?> sub : type.getPermittedSubclasses()) {
            if (sub.isSealed()) {
                collectLeaves(sub, out);
            } else if (sub.isInterface() || Modifier.isAbstract(sub.getModifiers())) {
                throw new IllegalArgumentException(type.getName() + ": non-sealed abstract "
                        + "subtype " + sub.getName() + " cannot be mapped");
            } else {
                out.add(sub);
            }
        }
    }

    // ------------------------------------------------------------------ properties

    private static boolean hasId(AnnotatedElement[] elements) {
        int n = 0;
        for (AnnotatedElement e : elements) {
            if (e.isAnnotationPresent(RgnId.class)) {
                n++;
            }
        }
        if (n > 1) {
            throw new IllegalArgumentException("more than one @RgnId property");
        }
        return n == 1;
    }

    /** The property rules (shared with the annotation processor, PD-111). */
    private static <T> void addProperty(ObjectCodec.Builder<T> b, Class<T> owner,
            AnnotatedElement e, String javaName, Class<?> raw, Type generic, boolean explicitId,
            Function<T, Object> getter, boolean reflective) {
        String where = owner.getName() + "." + javaName;
        Object absent = absent(raw);
        if (e.isAnnotationPresent(RgnIgnore.class)) {
            b.property(ObjectCodec.Kind.IGNORED, "", null, null, absent);
            return;
        }
        RgnField renamed = e.getAnnotation(RgnField.class);
        String name = e.isAnnotationPresent(RgnId.class) ? "_id"
                : renamed != null ? renamed.value()
                : !explicitId && "id".equals(javaName) ? "_id" : javaName;
        try {
            if (e.isAnnotationPresent(RgnRev.class)) {
                if (raw != String.class) {
                    throw new IllegalArgumentException("@RgnRev needs a String");
                }
                b.property(ObjectCodec.Kind.READ_ONLY, "_rev", Values.STRING, getter, null);
            } else if (e.isAnnotationPresent(RgnCounter.class)) {
                if (raw != long.class && raw != Long.class) {
                    throw new IllegalArgumentException("@RgnCounter needs a long or Long");
                }
                b.property(ObjectCodec.Kind.READ_ONLY, name, Values.COUNTER, getter, absent);
            } else if (raw == Optional.class) {
                b.property(ObjectCodec.Kind.OPTIONAL, name, codecOf(argument(generic, 0), null, reflective),
                        getter, absent);
            } else {
                b.property(ObjectCodec.Kind.FIELD, name, codecOf(generic, e, reflective), getter, absent);
            }
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(where + ": " + ex.getMessage(), ex);
        }
    }

    private static Object absent(Class<?> raw) {
        if (raw == Optional.class) {
            return Optional.empty();
        }
        if (!raw.isPrimitive()) {
            return null;
        }
        return raw == long.class ? (Object) 0L : raw == int.class ? (Object) 0
                : raw == short.class ? (Object) (short) 0 : raw == double.class ? (Object) 0.0
                : raw == float.class ? (Object) 0.0f : raw == boolean.class ? (Object) false
                : null;
    }

    /** The codec of a property or element type; {@code e} carries the property annotations. */
    private static ValueCodec<?> codecOf(Type t, AnnotatedElement e, boolean reflective) {
        RgnVector vector = e == null ? null : e.getAnnotation(RgnVector.class);
        boolean geo = e != null && e.isAnnotationPresent(RgnGeoPoint.class);
        if (vector != null && t != float[].class) {
            throw new IllegalArgumentException("@RgnVector needs a float[]");
        }
        if (geo && t != double[].class) {
            throw new IllegalArgumentException("@RgnGeoPoint needs a double[]");
        }
        if (t instanceof ParameterizedType p) {
            if (p.getRawType() == List.class) {
                return Values.list(codecOf(argument(p, 0), null, reflective));
            }
            if (p.getRawType() == Map.class) {
                if (argument(p, 0) != String.class) {
                    throw new IllegalArgumentException("map keys must be String");
                }
                return Values.map(codecOf(argument(p, 1), null, reflective));
            }
            throw unsupported(t);
        }
        if (!(t instanceof Class<?> c)) {
            throw unsupported(t);
        }
        if (c == long.class || c == Long.class) {
            return Values.LONG;
        } else if (c == int.class || c == Integer.class) {
            return Values.INT;
        } else if (c == short.class || c == Short.class) {
            return Values.SHORT;
        } else if (c == double.class || c == Double.class) {
            return Values.DOUBLE;
        } else if (c == float.class || c == Float.class) {
            return Values.FLOAT;
        } else if (c == boolean.class || c == Boolean.class) {
            return Values.BOOLEAN;
        } else if (c == String.class) {
            return Values.STRING;
        } else if (c == BigDecimal.class) {
            return Values.DECIMAL;
        } else if (c == byte[].class) {
            return Values.BYTES;
        } else if (c == float[].class) {
            return Values.vector(vector == null ? 0 : vector.value());
        } else if (c == double[].class && geo) {
            return Values.GEO_POINT;
        } else if (c == Instant.class) {
            return Values.INSTANT;
        } else if (c == OffsetDateTime.class) {
            return Values.OFFSET_DATE_TIME;
        } else if (c == ZonedDateTime.class) {
            return Values.ZONED_DATE_TIME;
        } else if (c == UUID.class) {
            return Values.UUID_CODEC;
        } else if (c == ObjectId.class) {
            return Values.OBJECT_ID;
        } else if (c == RDocument.class) {
            return Values.DOCUMENT;
        } else if (c == Object.class) {
            return Values.ANY;
        } else if (c.isEnum()) {
            return enumCodec(c);
        } else if (c.isPrimitive() || c.isArray() || isJdk(c) || c == List.class
                || c == Map.class) {
            throw unsupported(c);
        }
        return Values.lazy(() -> resolve(c, reflective));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static ValueCodec<?> enumCodec(Class<?> c) {
        return Values.enumOf((Class) c);
    }

    private static Type argument(Type t, int i) {
        if (!(t instanceof ParameterizedType p)) {
            throw new IllegalArgumentException("raw type " + t.getTypeName());
        }
        return p.getActualTypeArguments()[i];
    }

    private static boolean isJdk(Class<?> c) {
        String n = c.getName();
        return n.startsWith("java.") || n.startsWith("javax.") || n.startsWith("jdk.");
    }

    private static IllegalArgumentException unsupported(Type t) {
        return new IllegalArgumentException("unsupported type " + t.getTypeName());
    }

    // ------------------------------------------------------------------ method handles

    private static MethodHandles.Lookup lookup(Class<?> type) {
        // A named driver module reads only what it declares: add the edge before the lookup.
        Mapper.class.getModule().addReads(type.getModule());
        try {
            return MethodHandles.privateLookupIn(type, MethodHandles.lookup());
        } catch (IllegalAccessException e) {
            throw inaccessible(type, e);
        }
    }

    private static <T> Function<T, Object> function(MethodHandle getter) {
        return v -> {
            try {
                return getter.invoke(v);
            } catch (Throwable e) {
                throw rethrow(e);
            }
        };
    }

    private static RuntimeException rethrow(Throwable e) {
        if (e instanceof RuntimeException r) {
            return r;
        }
        if (e instanceof Error err) {
            throw err;
        }
        return new IllegalStateException(e);
    }

    private static IllegalArgumentException inaccessible(Class<?> type, Exception e) {
        return new IllegalArgumentException("cannot access " + type.getName() + " (in a named "
                + "module, open its package to io.rustegon.driver)", e);
    }
}
