// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! SST properties block (storage-engine.md §4): statistics the engine needs without scanning data
//! (MANIFEST bookkeeping, compaction scoring, time-bounded iteration).
//!
//! Encoded as a bytewise-ordered block of `name → value`. Engine properties use names
//! `rustegon.<name>` with `u64` little-endian values (strings as raw UTF-8); caller-supplied
//! properties (e.g. min/max MVCC timestamps and range-id hints set by the MVCC layer in M2) use
//! `user.<name>` with opaque bytes. Unknown `rustegon.*` names are ignored so that newer writers
//! can add statistics without breaking older readers.

use std::collections::BTreeMap;

use bytes::Bytes;

use super::block::{Block, BlockBuilder, KeyOrder};
use crate::{
    coding::Reader,
    error::{Result, StorageError},
    key::SeqNo,
};

const ENGINE_PREFIX: &str = "rustegon.";
const USER_PREFIX: &str = "user.";

/// Statistics and metadata of one SST.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Properties {
    /// Number of entries (all kinds).
    pub entries: u64,
    /// Point tombstones (`Delete` and `SingleDelete`).
    pub deletions: u64,
    /// Merge operands.
    pub merges: u64,
    /// Sum of encoded internal key lengths.
    pub raw_key_bytes: u64,
    /// Sum of value lengths.
    pub raw_value_bytes: u64,
    /// Number of data blocks.
    pub data_blocks: u64,
    /// Bytes of the data block area, trailers included.
    pub data_bytes: u64,
    /// Uncompressed size of all data blocks; `data_raw_bytes / data_bytes` is the compression
    /// ratio reported per file (TC-CMP-004).
    pub data_raw_bytes: u64,
    /// Data blocks stored compressed; the others fell back to raw (storage-engine.md §6).
    pub data_compressed_blocks: u64,
    /// Number of index partitions.
    pub index_partitions: u64,
    /// Bytes of all index blocks (partitions and top level), trailers included.
    pub index_bytes: u64,
    /// Bytes of the filter block, trailer included (0 without filter).
    pub filter_bytes: u64,
    /// Smallest seqno in the file (0 if empty).
    pub min_seqno: SeqNo,
    /// Largest seqno in the file (0 if empty).
    pub max_seqno: SeqNo,
    /// Name of the prefix extractor the filter was built with (empty without filter).
    pub filter_prefix_extractor: String,
    /// Caller-supplied properties.
    pub user: BTreeMap<String, Vec<u8>>,
}

impl Properties {
    fn numeric_fields(&self) -> [(&'static str, u64); 14] {
        [
            ("data.blocks", self.data_blocks),
            ("data.bytes", self.data_bytes),
            ("data.compressed.blocks", self.data_compressed_blocks),
            ("data.raw.bytes", self.data_raw_bytes),
            ("deletions", self.deletions),
            ("entries", self.entries),
            ("filter.bytes", self.filter_bytes),
            ("index.bytes", self.index_bytes),
            ("index.partitions", self.index_partitions),
            ("merges", self.merges),
            ("raw.key.bytes", self.raw_key_bytes),
            ("raw.value.bytes", self.raw_value_bytes),
            ("seqno.max", self.max_seqno),
            ("seqno.min", self.min_seqno),
        ]
    }

    fn numeric_field_mut(&mut self, name: &str) -> Option<&mut u64> {
        Some(match name {
            "data.blocks" => &mut self.data_blocks,
            "data.bytes" => &mut self.data_bytes,
            "data.compressed.blocks" => &mut self.data_compressed_blocks,
            "data.raw.bytes" => &mut self.data_raw_bytes,
            "deletions" => &mut self.deletions,
            "entries" => &mut self.entries,
            "filter.bytes" => &mut self.filter_bytes,
            "index.bytes" => &mut self.index_bytes,
            "index.partitions" => &mut self.index_partitions,
            "merges" => &mut self.merges,
            "raw.key.bytes" => &mut self.raw_key_bytes,
            "raw.value.bytes" => &mut self.raw_value_bytes,
            "seqno.max" => &mut self.max_seqno,
            "seqno.min" => &mut self.min_seqno,
            _ => return None,
        })
    }

    /// Encodes the properties block contents.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut entries: BTreeMap<String, Vec<u8>> = self
            .numeric_fields()
            .into_iter()
            .map(|(name, v)| (format!("{ENGINE_PREFIX}{name}"), v.to_le_bytes().to_vec()))
            .collect();
        entries.insert(
            format!("{ENGINE_PREFIX}filter.prefix_extractor"),
            self.filter_prefix_extractor.as_bytes().to_vec(),
        );
        for (name, value) in &self.user {
            entries.insert(format!("{USER_PREFIX}{name}"), value.clone());
        }
        let mut block = BlockBuilder::new(1);
        for (name, value) in &entries {
            block.add(name.as_bytes(), value)?;
        }
        Ok(block.finish())
    }

    /// Decodes a properties block.
    pub(crate) fn decode(contents: Bytes) -> Result<Self> {
        let corrupt = |what: String| StorageError::corruption(format!("properties: {what}"));
        let mut props = Self::default();
        let mut it = Block::new(contents)?.cursor(KeyOrder::Bytewise);
        it.seek_to_first()?;
        while it.valid() {
            let name = std::str::from_utf8(it.key())
                .map_err(|_| corrupt("non UTF-8 property name".into()))?;
            if let Some(user) = name.strip_prefix(USER_PREFIX) {
                props
                    .user
                    .insert(user.to_owned(), it.value_bytes().to_vec());
            } else if let Some(engine) = name.strip_prefix(ENGINE_PREFIX) {
                if engine == "filter.prefix_extractor" {
                    props.filter_prefix_extractor = String::from_utf8(it.value_bytes().to_vec())
                        .map_err(|_| corrupt("non UTF-8 prefix extractor".into()))?;
                } else if let Some(field) = props.numeric_field_mut(engine) {
                    *field = Reader::new(it.value_bytes())
                        .u64()
                        .ok_or_else(|| corrupt(format!("bad value for {name}")))?;
                }
            }
            it.next()?;
        }
        Ok(props)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn properties_round_trip_including_user_entries() {
        let mut props = Properties {
            entries: 10,
            deletions: 2,
            merges: 1,
            raw_key_bytes: 100,
            raw_value_bytes: 1000,
            data_blocks: 3,
            data_bytes: 1200,
            data_raw_bytes: 3000,
            data_compressed_blocks: 2,
            index_partitions: 1,
            index_bytes: 80,
            filter_bytes: 40,
            min_seqno: 5,
            max_seqno: 99,
            filter_prefix_extractor: "rustegon.full_key".into(),
            user: BTreeMap::new(),
        };
        props.user.insert("mvcc.ts.min".into(), vec![1, 2, 3]);
        let decoded = Properties::decode(Bytes::from(props.encode().unwrap())).unwrap();
        assert_eq!(decoded, props);
    }

    #[test]
    fn unknown_engine_properties_are_ignored() {
        let mut block = BlockBuilder::new(1);
        block.add(b"rustegon.entries", &7u64.to_le_bytes()).unwrap();
        block.add(b"rustegon.zz.future", b"anything").unwrap();
        let props = Properties::decode(Bytes::from(block.finish())).unwrap();
        assert_eq!(props.entries, 7);
    }
}
