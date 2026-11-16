// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

/**
 * Update builders (java-driver.md §3, PD-070; operation ids {@code Update.*} of
 * {@code drivers/conformance/model.yaml}). Each returns an {@link Update} with one operator;
 * chain further operators on it ({@code Updates.set("a", 1).inc("n", 1)}).
 */
public final class Updates {
    private Updates() {}

    /**
     * Sets {@code path} to {@code value}.
     *
     * @param path field path
     * @param value the value
     * @return the update
     */
    public static Update set(String path, Object value) {
        return Update.NONE.set(path, value);
    }

    /**
     * Removes {@code path}.
     *
     * @param path field path
     * @return the update
     */
    public static Update unset(String path) {
        return Update.NONE.unset(path);
    }

    /**
     * Adds {@code by} to the number at {@code path}.
     *
     * @param path field path
     * @param by the increment
     * @return the update
     */
    public static Update inc(String path, Object by) {
        return Update.NONE.inc(path, by);
    }

    /**
     * Multiplies the number at {@code path} by {@code by}.
     *
     * @param path field path
     * @param by the factor
     * @return the update
     */
    public static Update mul(String path, Object by) {
        return Update.NONE.mul(path, by);
    }

    /**
     * Sets {@code path} to {@code value} if that is smaller.
     *
     * @param path field path
     * @param value the value
     * @return the update
     */
    public static Update min(String path, Object value) {
        return Update.NONE.min(path, value);
    }

    /**
     * Sets {@code path} to {@code value} if that is larger.
     *
     * @param path field path
     * @param value the value
     * @return the update
     */
    public static Update max(String path, Object value) {
        return Update.NONE.max(path, value);
    }

    /**
     * Appends {@code value} to the array at {@code path}.
     *
     * @param path field path
     * @param value the element
     * @return the update
     */
    public static Update push(String path, Object value) {
        return Update.NONE.push(path, value);
    }

    /**
     * Appends {@code value} to the array at {@code path} unless already present.
     *
     * @param path field path
     * @param value the element
     * @return the update
     */
    public static Update addToSet(String path, Object value) {
        return Update.NONE.addToSet(path, value);
    }

    /**
     * Removes every element equal to {@code value} from the array at {@code path}.
     *
     * @param path field path
     * @param value the element
     * @return the update
     */
    public static Update pull(String path, Object value) {
        return Update.NONE.pull(path, value);
    }

    /**
     * Removes the first element of the array at {@code path}.
     *
     * @param path field path
     * @return the update
     */
    public static Update popFirst(String path) {
        return Update.NONE.popFirst(path);
    }

    /**
     * Removes the last element of the array at {@code path}.
     *
     * @param path field path
     * @return the update
     */
    public static Update popLast(String path) {
        return Update.NONE.popLast(path);
    }

    /**
     * Renames the field {@code from} to {@code to}.
     *
     * @param from current path
     * @param to new path
     * @return the update
     */
    public static Update rename(String from, String to) {
        return Update.NONE.rename(from, to);
    }

    /**
     * Sets {@code path} to the server's current datetime.
     *
     * @param path field path
     * @return the update
     */
    public static Update currentDate(String path) {
        return Update.NONE.currentDate(path);
    }

    /**
     * The operators of {@code updates}, in order.
     *
     * @param updates the updates
     * @return the combined update
     */
    public static Update combine(Update... updates) {
        Update u = Update.NONE;
        for (Update x : updates) {
            u = u.combine(x);
        }
        return u;
    }
}
