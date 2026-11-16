// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.processor;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.Messager;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.AnnotationValue;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.PackageElement;
import javax.lang.model.element.RecordComponentElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.ElementFilter;
import javax.tools.Diagnostic;

/**
 * Generates zero-reflection codecs for {@code @RustegonDocument} types (java-driver.md §5,
 * TC-DRV-JAVA-021): {@code <Type>_RgnCodec} (a {@code public static final DocumentCodec<Type>
 * INSTANCE} built from lambdas over {@code ObjectCodec} / {@code SealedCodec}) and the field-name
 * metamodel {@code <Type>_} ({@code Filters.eq(Order_.status, "paid")}). Types an annotated type
 * uses (nested documents, permitted subtypes) are generated too.
 *
 * <p>The property rules mirror {@code io.rustegon.driver.mapping.Mapper} (the run-time
 * {@code MethodHandles} mapper) exactly, so both write identical documents (TC-DRV-JAVA-022). The
 * processor depends on nothing but the JDK: annotations are matched by name and the code is
 * written as text.
 */
@SupportedAnnotationTypes(RustegonProcessor.PKG + ".RustegonDocument")
public final class RustegonProcessor extends AbstractProcessor {
    static final String PKG = "io.rustegon.driver.mapping";
    private static final String RDOC = "io.rustegon.driver.rdoc";

    /** Types already generated (or found compiled) in this compilation. */
    private final Set<String> done = new HashSet<>();

    /** Creates the processor (instantiated by javac through the service loader). */
    public RustegonProcessor() {}

    @Override
    public SourceVersion getSupportedSourceVersion() {
        return SourceVersion.latestSupported();
    }

    /** A mapping error, reported on {@link #element}. */
    private static final class MappingError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final transient Element element;

        MappingError(String message, Element element) {
            super(message);
            this.element = element;
        }
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment round) {
        TypeElement marker = processingEnv.getElementUtils().getTypeElement(PKG
                + ".RustegonDocument");
        if (marker == null) {
            return false;
        }
        Deque<TypeElement> work = new ArrayDeque<>();
        for (Element e : round.getElementsAnnotatedWith(marker)) {
            if (e instanceof TypeElement t) {
                work.add(t);
            }
        }
        Messager messager = processingEnv.getMessager();
        while (!work.isEmpty()) {
            TypeElement t = work.poll();
            String name = t.getQualifiedName().toString();
            if (!done.add(name)) {
                continue;
            }
            try {
                generate(t, work);
            } catch (MappingError e) {
                messager.printMessage(Diagnostic.Kind.ERROR, e.getMessage(), e.element);
            } catch (IOException e) {
                messager.printMessage(Diagnostic.Kind.ERROR, "cannot write the codec of " + name
                        + ": " + e, t);
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ generation

    private void generate(TypeElement t, Deque<TypeElement> work) throws IOException {
        String pkg = packageOf(t);
        String flat = flatName(t);
        String codecName = flat + "_RgnCodec";
        String qualifiedCodec = pkg.isEmpty() ? codecName : pkg + "." + codecName;
        if (processingEnv.getElementUtils().getTypeElement(qualifiedCodec) != null) {
            return; // compiled earlier (another module or a previous build of a library)
        }
        if (!t.getTypeParameters().isEmpty()) {
            throw new MappingError(t + ": generic types are not mapped", t);
        }
        String type = t.getQualifiedName().toString();
        StringBuilder init = new StringBuilder();
        List<String> metamodel = new ArrayList<>();
        if (t.getModifiers().contains(Modifier.SEALED)) {
            sealed(t, init, work);
        } else if (t.getKind() == ElementKind.RECORD) {
            record(t, init, metamodel, work);
        } else if (t.getKind() == ElementKind.CLASS
                && !t.getModifiers().contains(Modifier.ABSTRACT)) {
            pojo(t, init, metamodel, work);
        } else {
            throw new MappingError(t + " is not a mappable document type (record, sealed type "
                    + "or concrete class)", t);
        }
        StringBuilder src = new StringBuilder();
        header(src, pkg);
        src.append("/** The codec of {@link ").append(type).append("}, generated by "
                + "rustegon-processor. */\n")
            .append("@SuppressWarnings({\"unchecked\", \"rawtypes\"})\n")
            .append("public final class ").append(codecName).append(" {\n")
            .append("    /** The codec. */\n")
            .append("    public static final ").append(PKG).append(".DocumentCodec<").append(type)
            .append("> INSTANCE = ").append(init).append(";\n\n")
            .append("    private ").append(codecName).append("() {}\n}\n");
        write(qualifiedCodec, src, t);
        if (!metamodel.isEmpty()) {
            String metaName = flat + "_";
            StringBuilder m = new StringBuilder();
            header(m, pkg);
            m.append("/** Document field names of {@link ").append(type).append("}, generated by "
                    + "rustegon-processor. */\n")
                .append("public final class ").append(metaName).append(" {\n");
            for (String line : metamodel) {
                m.append(line);
            }
            m.append("\n    private ").append(metaName).append("() {}\n}\n");
            write(pkg.isEmpty() ? metaName : pkg + "." + metaName, m, t);
        }
    }

    private void sealed(TypeElement t, StringBuilder init, Deque<TypeElement> work) {
        if (t.getKind() != ElementKind.INTERFACE && !t.getModifiers().contains(Modifier.ABSTRACT)) {
            throw new MappingError(t + ": only sealed interfaces and sealed abstract classes are "
                    + "mapped polymorphically", t);
        }
        AnnotationMirror root = annotation(t, "RgnDiscriminator");
        String field = root == null ? "_type" : (String) value(root, "field");
        init.append("io.rustegon.driver.mapping.SealedCodec.builder(")
            .append(t.getQualifiedName()).append(".class, ").append(literal(field)).append(")");
        List<TypeElement> leaves = new ArrayList<>();
        leaves(t, leaves);
        for (TypeElement leaf : leaves) {
            AnnotationMirror d = annotation(leaf, "RgnDiscriminator");
            String tag = d == null || ((String) value(d, "value")).isEmpty()
                    ? leaf.getSimpleName().toString() : (String) value(d, "value");
            init.append("\n            .subtype(").append(literal(tag)).append(", ")
                .append(leaf.getQualifiedName()).append(".class, ").append(nested(leaf, work))
                .append(")");
        }
        init.append("\n            .build()");
    }

    private void leaves(TypeElement t, List<TypeElement> out) {
        for (TypeMirror m : t.getPermittedSubclasses()) {
            TypeElement sub = (TypeElement) ((DeclaredType) m).asElement();
            if (sub.getModifiers().contains(Modifier.SEALED)) {
                leaves(sub, out);
            } else if (sub.getKind() == ElementKind.INTERFACE
                    || sub.getModifiers().contains(Modifier.ABSTRACT)) {
                throw new MappingError(t + ": non-sealed abstract subtype " + sub
                        + " cannot be mapped", t);
            } else {
                out.add(sub);
            }
        }
    }

    private void record(TypeElement t, StringBuilder init, List<String> metamodel,
            Deque<TypeElement> work) {
        List<? extends RecordComponentElement> components = t.getRecordComponents();
        boolean explicitId = hasId(components);
        StringBuilder creator = new StringBuilder("a -> new " + t.getQualifiedName() + "(");
        init.append("io.rustegon.driver.mapping.ObjectCodec.builder(").append(t.getQualifiedName())
            .append(".class)");
        for (int i = 0; i < components.size(); i++) {
            RecordComponentElement c = components.get(i);
            String name = c.getSimpleName().toString();
            property(init, metamodel, c, name, c.asType(), "v -> v." + name + "()", explicitId,
                    work);
            creator.append(i == 0 ? "" : ", ").append(cast(c.asType())).append("a[").append(i)
                .append("]");
        }
        init.append("\n            .build(").append(creator).append("))");
    }

    private void pojo(TypeElement t, StringBuilder init, List<String> metamodel,
            Deque<TypeElement> work) {
        String type = t.getQualifiedName().toString();
        boolean ctor = false;
        for (ExecutableElement c : ElementFilter.constructorsIn(t.getEnclosedElements())) {
            ctor |= c.getParameters().isEmpty() && accessible(c, t);
        }
        if (!ctor || t.getNestingKind().isNested() && !t.getModifiers().contains(Modifier.STATIC)) {
            throw new MappingError(t + " needs an accessible no-argument constructor", t);
        }
        List<VariableElement> fields = new ArrayList<>();
        for (TypeElement c = t; c != null && !c.getQualifiedName().contentEquals(
                "java.lang.Object"); c = superclass(c)) {
            List<VariableElement> own = new ArrayList<>();
            for (VariableElement f : ElementFilter.fieldsIn(c.getEnclosedElements())) {
                if (!f.getModifiers().contains(Modifier.STATIC)
                        && !f.getModifiers().contains(Modifier.TRANSIENT)) {
                    own.add(f);
                }
            }
            fields.addAll(0, own);
        }
        boolean explicitId = hasId(fields);
        StringBuilder creator = new StringBuilder("a -> { " + type + " o = new " + type + "();");
        init.append("io.rustegon.driver.mapping.ObjectCodec.builder(").append(type)
            .append(".class)");
        for (int i = 0; i < fields.size(); i++) {
            VariableElement f = fields.get(i);
            String name = f.getSimpleName().toString();
            boolean direct = accessible(f, t);
            String getter = direct ? "v -> v." + name : "v -> v." + accessor(t, f, true) + "()";
            property(init, metamodel, f, name, f.asType(), getter, explicitId, work);
            if (annotation(f, "RgnIgnore") != null) {
                continue;
            }
            if (f.getModifiers().contains(Modifier.FINAL)) {
                throw new MappingError(t + "." + name + ": final fields of a class are not mapped "
                        + "(use a record)", f);
            }
            String v = cast(f.asType()) + "a[" + i + "]";
            creator.append(direct ? " o." + name + " = " + v + ";"
                    : " o." + accessor(t, f, false) + "(" + v + ");");
        }
        creator.append(" return o; }");
        init.append("\n            .build(").append(creator).append(")");
    }

    /** The property rules of {@code Mapper.addProperty}. */
    private void property(StringBuilder init, List<String> metamodel, Element e, String javaName,
            TypeMirror type, String getter, boolean explicitId, Deque<TypeElement> work) {
        String absent = absent(type);
        if (annotation(e, "RgnIgnore") != null) {
            init.append("\n            .property(").append(PKG)
                .append(".ObjectCodec.Kind.IGNORED, \"\", null, null, ").append(absent).append(")");
            return;
        }
        AnnotationMirror renamed = annotation(e, "RgnField");
        String name = annotation(e, "RgnId") != null ? "_id"
                : renamed != null ? (String) value(renamed, "value")
                : !explicitId && "id".equals(javaName) ? "_id" : javaName;
        String kind;
        String codec;
        if (annotation(e, "RgnRev") != null) {
            if (!isType(type, "java.lang.String")) {
                throw new MappingError(e + ": @RgnRev needs a String", e);
            }
            kind = "READ_ONLY";
            name = "_rev";
            codec = PKG + ".Values.STRING";
            absent = "null";
        } else if (annotation(e, "RgnCounter") != null) {
            if (type.getKind() != TypeKind.LONG && !isType(type, "java.lang.Long")) {
                throw new MappingError(e + ": @RgnCounter needs a long or Long", e);
            }
            kind = "READ_ONLY";
            codec = PKG + ".Values.COUNTER";
        } else if (isType(type, "java.util.Optional")) {
            kind = "OPTIONAL";
            codec = codec(argument(type, 0, e), null, work);
        } else {
            kind = "FIELD";
            codec = codec(type, e, work);
        }
        init.append("\n            .property(").append(PKG).append(".ObjectCodec.Kind.")
            .append(kind).append(", ").append(literal(name)).append(", ").append(codec)
            .append(", ").append(getter).append(", ").append(absent).append(")");
        metamodel.add("    /** Field of {@code " + javaName + "}. */\n    public static final "
                + "String " + javaName + " = " + literal(name) + ";\n");
    }

    /** The codec expression of a property or element type (rules of {@code Mapper.codecOf}). */
    private String codec(TypeMirror t, Element e, Deque<TypeElement> work) {
        AnnotationMirror vector = e == null ? null : annotation(e, "RgnVector");
        boolean geo = e != null && annotation(e, "RgnGeoPoint") != null;
        boolean floatArray = t instanceof ArrayType a
                && a.getComponentType().getKind() == TypeKind.FLOAT;
        boolean doubleArray = t instanceof ArrayType a
                && a.getComponentType().getKind() == TypeKind.DOUBLE;
        if (vector != null && !floatArray) {
            throw new MappingError(e + ": @RgnVector needs a float[]", e);
        }
        if (geo && !doubleArray) {
            throw new MappingError(e + ": @RgnGeoPoint needs a double[]", e);
        }
        String v = PKG + ".Values.";
        switch (t.getKind()) {
            case LONG: return v + "LONG";
            case INT: return v + "INT";
            case SHORT: return v + "SHORT";
            case DOUBLE: return v + "DOUBLE";
            case FLOAT: return v + "FLOAT";
            case BOOLEAN: return v + "BOOLEAN";
            case ARRAY:
                TypeKind c = ((ArrayType) t).getComponentType().getKind();
                if (c == TypeKind.BYTE) {
                    return v + "BYTES";
                }
                if (floatArray) {
                    return v + "vector(" + (vector == null ? 0 : value(vector, "value")) + ")";
                }
                if (doubleArray && geo) {
                    return v + "GEO_POINT";
                }
                throw unsupported(t, e);
            case DECLARED:
                break;
            default:
                throw unsupported(t, e);
        }
        TypeElement el = (TypeElement) ((DeclaredType) t).asElement();
        String n = el.getQualifiedName().toString();
        switch (n) {
            case "java.lang.Long": return v + "LONG";
            case "java.lang.Integer": return v + "INT";
            case "java.lang.Short": return v + "SHORT";
            case "java.lang.Double": return v + "DOUBLE";
            case "java.lang.Float": return v + "FLOAT";
            case "java.lang.Boolean": return v + "BOOLEAN";
            case "java.lang.String": return v + "STRING";
            case "java.math.BigDecimal": return v + "DECIMAL";
            case "java.time.Instant": return v + "INSTANT";
            case "java.time.OffsetDateTime": return v + "OFFSET_DATE_TIME";
            case "java.time.ZonedDateTime": return v + "ZONED_DATE_TIME";
            case "java.util.UUID": return v + "UUID_CODEC";
            case RDOC + ".ObjectId": return v + "OBJECT_ID";
            case RDOC + ".RDocument": return v + "DOCUMENT";
            case "java.lang.Object": return v + "ANY";
            case "java.util.List": return v + "list(" + codec(argument(t, 0, e), null, work) + ")";
            case "java.util.Map":
                if (!isType(argument(t, 0, e), "java.lang.String")) {
                    throw new MappingError(where(e) + "map keys must be String", e);
                }
                return v + "map(" + codec(argument(t, 1, e), null, work) + ")";
            default:
                break;
        }
        if (el.getKind() == ElementKind.ENUM) {
            return v + "enumOf(" + n + ".class)";
        }
        if (n.startsWith("java.") || n.startsWith("javax.") || n.startsWith("jdk.")) {
            throw unsupported(t, e);
        }
        return nested(el, work);
    }

    private String nested(TypeElement el, Deque<TypeElement> work) {
        work.add(el);
        String pkg = packageOf(el);
        return PKG + ".Values.lazy(() -> " + (pkg.isEmpty() ? "" : pkg + ".") + flatName(el)
                + "_RgnCodec.INSTANCE)";
    }

    // ------------------------------------------------------------------ helpers

    private boolean hasId(List<? extends Element> elements) {
        int n = 0;
        for (Element e : elements) {
            if (annotation(e, "RgnId") != null) {
                n++;
                if (n > 1) {
                    throw new MappingError(e + ": more than one @RgnId property", e);
                }
            }
        }
        return n == 1;
    }

    private static AnnotationMirror annotation(Element e, String simpleName) {
        for (AnnotationMirror m : e.getAnnotationMirrors()) {
            if (((TypeElement) m.getAnnotationType().asElement()).getQualifiedName()
                    .contentEquals(PKG + "." + simpleName)) {
                return m;
            }
        }
        return null;
    }

    private Object value(AnnotationMirror m, String name) {
        for (Map.Entry<? extends ExecutableElement, ? extends AnnotationValue> en
                : processingEnv.getElementUtils().getElementValuesWithDefaults(m).entrySet()) {
            if (en.getKey().getSimpleName().contentEquals(name)) {
                return en.getValue().getValue();
            }
        }
        throw new IllegalStateException("no annotation value " + name);
    }

    private static boolean isType(TypeMirror t, String qualifiedName) {
        return t.getKind() == TypeKind.DECLARED && ((TypeElement) ((DeclaredType) t).asElement())
                .getQualifiedName().contentEquals(qualifiedName);
    }

    private static TypeMirror argument(TypeMirror t, int i, Element e) {
        List<? extends TypeMirror> args = ((DeclaredType) t).getTypeArguments();
        if (args.isEmpty()) {
            throw new MappingError(where(e) + "raw type " + t, e);
        }
        return args.get(i);
    }

    private static String where(Element e) {
        return e == null ? "" : e + ": ";
    }

    private static MappingError unsupported(TypeMirror t, Element e) {
        return new MappingError(where(e) + "unsupported type " + t, e);
    }

    private static String absent(TypeMirror t) {
        switch (t.getKind()) {
            case LONG: return "0L";
            case INT: return "0";
            case SHORT: return "(short) 0";
            case DOUBLE: return "0.0";
            case FLOAT: return "0.0f";
            case BOOLEAN: return "false";
            default: return isType(t, "java.util.Optional") ? "java.util.Optional.empty()" : "null";
        }
    }

    /** A cast of {@code Object} to the property type (boxed for primitives). */
    private String cast(TypeMirror t) {
        TypeMirror boxed = t.getKind().isPrimitive()
                ? processingEnv.getTypeUtils().boxedClass((javax.lang.model.type.PrimitiveType) t)
                    .asType()
                : t;
        return "(" + boxed + ") ";
    }

    private static boolean accessible(Element member, TypeElement from) {
        Set<Modifier> m = member.getModifiers();
        if (m.contains(Modifier.PRIVATE)) {
            return false;
        }
        TypeElement owner = (TypeElement) member.getEnclosingElement();
        return m.contains(Modifier.PUBLIC) || packageOf(owner).equals(packageOf(from));
    }

    /** The getter ({@code getX}/{@code isX}) or setter ({@code setX}) of a private field. */
    private String accessor(TypeElement t, VariableElement f, boolean getter) {
        String n = f.getSimpleName().toString();
        String cap = Character.toUpperCase(n.charAt(0)) + n.substring(1);
        for (ExecutableElement m : ElementFilter.methodsIn(processingEnv.getElementUtils()
                .getAllMembers(t))) {
            String mn = m.getSimpleName().toString();
            boolean match = getter
                    ? m.getParameters().isEmpty() && (mn.equals("get" + cap)
                        || mn.equals("is" + cap) && f.asType().getKind() == TypeKind.BOOLEAN)
                    : m.getParameters().size() == 1 && mn.equals("set" + cap);
            if (match && !m.getModifiers().contains(Modifier.STATIC) && accessible(m, t)) {
                return mn;
            }
        }
        throw new MappingError(t + "." + n + ": a private field needs an accessible "
                + (getter ? "getter" : "setter"), f);
    }

    private static TypeElement superclass(TypeElement t) {
        TypeMirror s = t.getSuperclass();
        return s.getKind() == TypeKind.DECLARED ? (TypeElement) ((DeclaredType) s).asElement()
                : null;
    }

    private static String packageOf(Element e) {
        while (!(e instanceof PackageElement)) {
            e = e.getEnclosingElement();
        }
        return ((PackageElement) e).getQualifiedName().toString();
    }

    /** Nested names joined by {@code _} ({@code Mapper.generatedCodecName}). */
    private static String flatName(TypeElement t) {
        String name = t.getSimpleName().toString();
        for (Element e = t.getEnclosingElement(); e instanceof TypeElement o;
                e = o.getEnclosingElement()) {
            name = o.getSimpleName() + "_" + name;
        }
        return name;
    }

    private static String literal(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                default -> {
                    if (c < 0x20 || c > 0x7e) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append('"').toString();
    }

    private static void header(StringBuilder src, String pkg) {
        src.append("// Generated by rustegon-processor (java-driver.md section 5). Do not edit.\n");
        if (!pkg.isEmpty()) {
            src.append("package ").append(pkg).append(";\n");
        }
        src.append('\n');
    }

    private void write(String qualifiedName, StringBuilder src, TypeElement origin)
            throws IOException {
        try (Writer w = processingEnv.getFiler().createSourceFile(qualifiedName, origin)
                .openWriter()) {
            w.write(src.toString());
        }
    }
}
