// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.util.List;

/**
 * Versions and capabilities of a node ({@code SessionService.GetServerInfo}, protocol.md §9).
 * Drivers gate features on {@link #features()}, never on version comparisons.
 *
 * @param serverVersion server version (semver)
 * @param protocolVersion wire protocol version {@code 1.<minor>}
 * @param features capability flags, e.g. {@code vector}
 * @param nodeAddresses client endpoints of the cluster nodes (topology hint)
 */
public record ServerInfo(String serverVersion, String protocolVersion, List<String> features,
        List<String> nodeAddresses) {
    /**
     * Copies the lists.
     *
     * @param serverVersion server version
     * @param protocolVersion protocol version
     * @param features capability flags (copied)
     * @param nodeAddresses node endpoints (copied)
     */
    public ServerInfo {
        features = List.copyOf(features);
        nodeAddresses = List.copyOf(nodeAddresses);
    }

    /**
     * Whether the server announces a capability.
     *
     * @param feature the flag
     * @return {@code true} if present
     */
    public boolean hasFeature(String feature) {
        return features.contains(feature);
    }
}
