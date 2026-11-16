// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import java.time.Duration;

/**
 * What a database, collection or transaction handle adds to its calls: the session whose
 * causality token travels with them, the transaction they join, and the per-handle overrides of
 * the operation timeout, read consistency and write concern ({@code null} = the client setting).
 * Handles are immutable; {@code with…} methods derive new contexts.
 */
record OpContext(ClientSession session, String txnId, Duration timeout,
        ReadConsistency readConsistency, Duration maxStaleness, WriteConcern writeConcern) {
    /** No session, no transaction, the client's settings. */
    static final OpContext NONE = new OpContext(null, null, null, null, null, null);

    OpContext withSession(ClientSession s) {
        return new OpContext(s, txnId, timeout, readConsistency, maxStaleness, writeConcern);
    }

    OpContext withTxn(String id) {
        return new OpContext(session, id, timeout, readConsistency, maxStaleness, writeConcern);
    }

    OpContext withTimeout(Duration t) {
        return new OpContext(session, txnId, t, readConsistency, maxStaleness, writeConcern);
    }

    OpContext withReadConsistency(ReadConsistency rc, Duration staleness) {
        return new OpContext(session, txnId, timeout, rc, staleness, writeConcern);
    }

    OpContext withWriteConcern(WriteConcern wc) {
        return new OpContext(session, txnId, timeout, readConsistency, maxStaleness, wc);
    }
}
