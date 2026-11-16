// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The builder DSL of drivers/conformance/README.md §4 translated into the driver's builder
 * calls ({@link Filters}, {@link Updates}, {@link Sorts}, {@link Projections}); used by the AST
 * vectors and the conformance runner. {@code v} converts DSL values (YAML nodes) to driver
 * values.
 */
final class Dsl {
    private Dsl() {}

    @SuppressWarnings("unchecked")
    static Filter filter(Object dsl, Function<Object, Object> v) {
        Map<String, Object> m = (Map<String, Object>) dsl;
        if (m.isEmpty()) {
            return Filters.empty();
        }
        if (m.size() != 1) {
            throw new IllegalArgumentException("a filter has one key: " + m);
        }
        String k = m.keySet().iterator().next();
        Object a = m.get(k);
        List<Object> l = a instanceof List ? (List<Object>) a : List.of();
        return switch (k) {
            case "eq" -> Filters.eq(path(l), v.apply(l.get(1)));
            case "ne" -> Filters.ne(path(l), v.apply(l.get(1)));
            case "gt" -> Filters.gt(path(l), v.apply(l.get(1)));
            case "gte" -> Filters.gte(path(l), v.apply(l.get(1)));
            case "lt" -> Filters.lt(path(l), v.apply(l.get(1)));
            case "lte" -> Filters.lte(path(l), v.apply(l.get(1)));
            case "in" -> Filters.in(path(l), (Collection<?>) v.apply(l.get(1)));
            case "nin" -> Filters.nin(path(l), (Collection<?>) v.apply(l.get(1)));
            case "containsAny" -> Filters.containsAny(path(l), (Collection<?>) v.apply(l.get(1)));
            case "containsAll" -> Filters.containsAll(path(l), (Collection<?>) v.apply(l.get(1)));
            case "contains" -> Filters.contains(path(l), v.apply(l.get(1)));
            case "exists" -> Filters.exists(path(l), (Boolean) l.get(1));
            case "isNull" -> Filters.isNull((String) a);
            case "elemMatch" -> Filters.elemMatch(path(l), filter(l.get(1), v));
            case "like" -> Filters.like(path(l), (String) l.get(1));
            case "regex" -> Filters.regex(path(l), (String) l.get(1));
            case "and" -> Filters.and(filters(l, v));
            case "or" -> Filters.or(filters(l, v));
            case "not" -> Filters.not(filter(a, v));
            case "id" -> Filters.id(v.apply(a));
            default -> throw new IllegalArgumentException("unknown filter " + k);
        };
    }

    private static String path(List<Object> l) {
        return (String) l.get(0);
    }

    private static Filter[] filters(List<Object> l, Function<Object, Object> v) {
        Filter[] out = new Filter[l.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = filter(l.get(i), v);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    static Update update(Object dsl, Function<Object, Object> v) {
        Update u = Update.NONE;
        for (Object o : (List<Object>) dsl) {
            Map<String, Object> m = (Map<String, Object>) o;
            String k = m.keySet().iterator().next();
            Object a = m.get(k);
            List<Object> l = a instanceof List ? (List<Object>) a : List.of();
            u = switch (k) {
                case "set" -> u.set(path(l), v.apply(l.get(1)));
                case "unset" -> u.unset((String) a);
                case "inc" -> u.inc(path(l), v.apply(l.get(1)));
                case "mul" -> u.mul(path(l), v.apply(l.get(1)));
                case "min" -> u.min(path(l), v.apply(l.get(1)));
                case "max" -> u.max(path(l), v.apply(l.get(1)));
                case "push" -> u.push(path(l), v.apply(l.get(1)));
                case "addToSet" -> u.addToSet(path(l), v.apply(l.get(1)));
                case "pull" -> u.pull(path(l), v.apply(l.get(1)));
                case "pop" -> "first".equals(l.get(1)) ? u.popFirst(path(l)) : u.popLast(path(l));
                case "rename" -> u.rename(path(l), (String) l.get(1));
                case "currentDate" -> u.currentDate((String) a);
                case "replace" -> u.combine(Update.replaceWith(v.apply(a)));
                default -> throw new IllegalArgumentException("unknown update " + k);
            };
        }
        return u;
    }

    @SuppressWarnings("unchecked")
    static Sort sort(Object dsl) {
        List<Sort> keys = new ArrayList<>();
        for (String p : (List<String>) dsl) {
            keys.add(p.startsWith("-") ? Sorts.desc(p.substring(1)) : Sorts.asc(p));
        }
        return Sorts.orderBy(keys.toArray(new Sort[0]));
    }

    @SuppressWarnings("unchecked")
    static Projection projection(Object dsl) {
        Map<String, Object> m = (Map<String, Object>) dsl;
        if (m.containsKey("include")) {
            return Projections.include(((List<String>) m.get("include")).toArray(new String[0]));
        }
        return Projections.exclude(((List<String>) m.get("exclude")).toArray(new String[0]));
    }
}
