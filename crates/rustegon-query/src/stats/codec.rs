// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Persisted statistics record, **stats format 1** (*Provisional (PD pending)*; query-engine.md
//! §2.1; fixtures `crates/rustegon-query/tests/fixtures/formats/stats/1/`).
//!
//! Key: `0x02 't' collection_id(u32 BE)` in the system namespace (`/sys/stats` of
//! database-engine.md §2.6; collection ids are cluster-unique, so the database id is not part
//! of the key). Value: a canonical `RDoc`, like the catalog descriptors:
//!
//! ```text
//! { stats_format: 1, type: "collection_stats", database_id, collection_id, row_count,
//!   total_bytes, sample_rows, collected_at: datetime,
//!   fields: [{ path, indexed: bool, rows_null, rows_missing, rows_array, ndv,
//!              hll: binary(4096 registers, p = 12),
//!              mcv: [{ value: binary(key element), fraction: float64 }],
//!              histogram: { lower: binary, buckets: [{ upper: binary, fraction, distinct }] },
//!              array_lengths: [int64 × 10] }],
//!   indexes: [{ index_id, entries, bytes }] }
//! ```
//! Integers are `int64` (ids fit in u32, counts ≥ 0); fractions are finite `float64` ≥ 0.
//! Decoding is strict, as for the catalog formats: an unknown field or a wrong type is
//! corruption (`RGN-5002`), because a new field means stats format 2 (implementation-rules.md
//! §6). Statistics are derived data: a reader that meets an unsupported format may also simply
//! recollect them.

use rustegon_common::{Error, ErrorCode};
use rustegon_doc::{Document, Value, keyspace::NS_SYSTEM, rdoc, value::BINARY_GENERIC};

use super::{
    histogram::{Bucket, Histogram},
    hll::HyperLogLog,
    model::{ARRAY_LENGTH_BOUNDS, CollectionStats, FieldStats, IndexSize, McvEntry},
};

/// Stats format written by this crate (the `stats_format` field).
pub const STATS_FORMAT: i64 = 1;
/// Sub-namespace byte of statistics records under `0x02`.
pub const SUB_STATS: u8 = b't';

const TYPE_STATS: &str = "collection_stats";
const TOP: &[&str] = &[
    "stats_format",
    "type",
    "database_id",
    "collection_id",
    "row_count",
    "total_bytes",
    "sample_rows",
    "collected_at",
    "fields",
    "indexes",
];
const FIELD: &[&str] = &[
    "path",
    "indexed",
    "rows_null",
    "rows_missing",
    "rows_array",
    "ndv",
    "hll",
    "mcv",
    "histogram",
    "array_lengths",
];
const MCV: &[&str] = &["value", "fraction"];
const HISTOGRAM: &[&str] = &["lower", "buckets"];
const BUCKET: &[&str] = &["upper", "fraction", "distinct"];
const INDEX: &[&str] = &["index_id", "entries", "bytes"];

/// Common prefix of every statistics record key (`0x02 't'`).
#[must_use]
pub fn stats_prefix() -> Vec<u8> {
    vec![NS_SYSTEM, SUB_STATS]
}

/// System key of the statistics record of `collection_id`.
#[must_use]
pub fn stats_key(collection_id: u32) -> Vec<u8> {
    let mut k = stats_prefix();
    k.extend_from_slice(&collection_id.to_be_bytes());
    k
}

fn count(v: u64) -> Result<Value, Error> {
    i64::try_from(v)
        .map(Value::Int64)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "statistic above i64::MAX"))
}

fn fraction(v: f64) -> Result<Value, Error> {
    if v.is_finite() && v >= 0.0 {
        Ok(Value::Float64(v))
    } else {
        Err(Error::new(
            ErrorCode::InvalidArgument,
            "fraction not finite and >= 0",
        ))
    }
}

fn bin(b: &[u8]) -> Value {
    Value::Binary {
        subtype: BINARY_GENERIC,
        data: b.to_vec(),
    }
}

fn obj(fields: Vec<(&str, Value)>) -> Result<Value, Error> {
    let fields = fields.into_iter().map(|(n, v)| (n.to_owned(), v)).collect();
    Ok(Value::Object(Document::try_from_fields(fields)?))
}

fn encode_field(f: &FieldStats) -> Result<Value, Error> {
    let mcv = f
        .mcv
        .iter()
        .map(|m| {
            obj(vec![
                ("value", bin(&m.value)),
                ("fraction", fraction(m.fraction)?),
            ])
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let buckets = f
        .histogram
        .buckets
        .iter()
        .map(|b| {
            obj(vec![
                ("upper", bin(&b.upper)),
                ("fraction", fraction(b.fraction)?),
                ("distinct", count(b.distinct)?),
            ])
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let lengths = f
        .array_lengths
        .iter()
        .map(|c| count(*c))
        .collect::<Result<Vec<_>, Error>>()?;
    obj(vec![
        ("path", Value::String(f.path.clone())),
        ("indexed", Value::Bool(f.indexed)),
        ("rows_null", count(f.rows_null)?),
        ("rows_missing", count(f.rows_missing)?),
        ("rows_array", count(f.rows_array)?),
        ("ndv", count(f.ndv)?),
        ("hll", bin(f.hll.registers())),
        ("mcv", Value::Array(mcv)),
        (
            "histogram",
            obj(vec![
                ("lower", bin(&f.histogram.lower)),
                ("buckets", Value::Array(buckets)),
            ])?,
        ),
        ("array_lengths", Value::Array(lengths)),
    ])
}

/// Encodes a statistics record (stats format 1, canonical `RDoc`).
///
/// # Errors
/// `RGN-1001` for a count above `i64::MAX` or a non-finite fraction; document codec errors.
pub fn encode_stats(s: &CollectionStats) -> Result<Vec<u8>, Error> {
    let fields = s
        .fields
        .iter()
        .map(encode_field)
        .collect::<Result<Vec<_>, Error>>()?;
    let indexes = s
        .indexes
        .iter()
        .map(|i| {
            obj(vec![
                ("index_id", Value::Int64(i64::from(i.index_id))),
                ("entries", count(i.entries)?),
                ("bytes", count(i.bytes)?),
            ])
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let Value::Object(doc) = obj(vec![
        ("stats_format", Value::Int64(STATS_FORMAT)),
        ("type", Value::String(TYPE_STATS.into())),
        ("database_id", Value::Int64(i64::from(s.database_id))),
        ("collection_id", Value::Int64(i64::from(s.collection_id))),
        ("row_count", count(s.row_count)?),
        ("total_bytes", count(s.total_bytes)?),
        ("sample_rows", count(s.sample_rows)?),
        ("collected_at", Value::DateTime(s.collected_at_ms)),
        ("fields", Value::Array(fields)),
        ("indexes", Value::Array(indexes)),
    ])?
    else {
        return Err(Error::new(
            ErrorCode::Internal,
            "stats record is not an object",
        ));
    };
    Ok(rdoc::encode(&doc)?)
}

fn corrupt(msg: impl Into<String>) -> Error {
    Error::new(
        ErrorCode::StorageCorruption,
        format!("stats record: {}", msg.into()),
    )
}

/// Strict reader over one object (rejects undeclared fields).
struct Obj<'a>(&'a Document);

impl<'a> Obj<'a> {
    fn new(v: &'a Value, allowed: &[&str]) -> Result<Self, Error> {
        let Value::Object(d) = v else {
            return Err(corrupt("expected an object"));
        };
        Self::of(d, allowed)
    }

    fn of(d: &'a Document, allowed: &[&str]) -> Result<Self, Error> {
        if let Some((name, _)) = d.iter().find(|(n, _)| !allowed.contains(n)) {
            return Err(corrupt(format!("unknown field {name:?}")));
        }
        Ok(Self(d))
    }

    fn req(&self, name: &str) -> Result<&'a Value, Error> {
        self.0
            .get(name)
            .ok_or_else(|| corrupt(format!("missing field {name}")))
    }

    fn count(&self, name: &str) -> Result<u64, Error> {
        match self.req(name)? {
            Value::Int64(v) => u64::try_from(*v).map_err(|_| corrupt(format!("{name} < 0"))),
            _ => Err(corrupt(format!("{name} is not an int64"))),
        }
    }

    fn id(&self, name: &str) -> Result<u32, Error> {
        u32::try_from(self.count(name)?).map_err(|_| corrupt(format!("{name} is not a u32")))
    }

    fn fraction(&self, name: &str) -> Result<f64, Error> {
        match self.req(name)? {
            Value::Float64(v) if v.is_finite() && *v >= 0.0 => Ok(*v),
            _ => Err(corrupt(format!("{name} is not a fraction"))),
        }
    }

    fn bytes(&self, name: &str) -> Result<Vec<u8>, Error> {
        match self.req(name)? {
            Value::Binary {
                subtype: BINARY_GENERIC,
                data,
            } => Ok(data.clone()),
            _ => Err(corrupt(format!("{name} is not generic binary"))),
        }
    }

    fn array(&self, name: &str) -> Result<&'a [Value], Error> {
        match self.req(name)? {
            Value::Array(v) => Ok(v),
            _ => Err(corrupt(format!("{name} is not an array"))),
        }
    }
}

fn decode_field(v: &Value) -> Result<FieldStats, Error> {
    let o = Obj::new(v, FIELD)?;
    let Value::String(path) = o.req("path")? else {
        return Err(corrupt("path is not a string"));
    };
    let Value::Bool(indexed) = o.req("indexed")? else {
        return Err(corrupt("indexed is not a bool"));
    };
    let hll = HyperLogLog::from_registers(o.bytes("hll")?)
        .ok_or_else(|| corrupt("hll registers malformed"))?;
    let mcv = o
        .array("mcv")?
        .iter()
        .map(|m| {
            let m = Obj::new(m, MCV)?;
            Ok(McvEntry {
                value: m.bytes("value")?,
                fraction: m.fraction("fraction")?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let h = Obj::new(o.req("histogram")?, HISTOGRAM)?;
    let buckets = h
        .array("buckets")?
        .iter()
        .map(|b| {
            let b = Obj::new(b, BUCKET)?;
            Ok(Bucket {
                upper: b.bytes("upper")?,
                fraction: b.fraction("fraction")?,
                distinct: b.count("distinct")?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let lengths = o.array("array_lengths")?;
    if lengths.len() != ARRAY_LENGTH_BOUNDS.len() {
        return Err(corrupt("array_lengths has the wrong length"));
    }
    let mut array_lengths = [0u64; ARRAY_LENGTH_BOUNDS.len()];
    for (slot, v) in array_lengths.iter_mut().zip(lengths) {
        *slot = match v {
            Value::Int64(c) => u64::try_from(*c).map_err(|_| corrupt("array length count < 0"))?,
            _ => return Err(corrupt("array length count is not an int64")),
        };
    }
    Ok(FieldStats {
        path: path.clone(),
        indexed: *indexed,
        rows_null: o.count("rows_null")?,
        rows_missing: o.count("rows_missing")?,
        rows_array: o.count("rows_array")?,
        ndv: o.count("ndv")?,
        hll,
        mcv,
        histogram: Histogram {
            lower: h.bytes("lower")?,
            buckets,
        },
        array_lengths,
    })
}

/// Decodes a record written by [`encode_stats`].
///
/// # Errors
/// `RGN-5002` for bytes that are not a valid stats-format-1 record (including another
/// `stats_format`).
pub fn decode_stats(bytes: &[u8]) -> Result<CollectionStats, Error> {
    let doc = rdoc::decode(bytes).map_err(|e| corrupt(format!("RDoc: {e}")))?;
    match doc.get("stats_format") {
        Some(Value::Int64(STATS_FORMAT)) => {}
        Some(Value::Int64(v)) => return Err(corrupt(format!("unsupported stats_format {v}"))),
        _ => return Err(corrupt("missing stats_format")),
    }
    let o = Obj::of(&doc, TOP)?;
    if !matches!(o.req("type")?, Value::String(t) if t == TYPE_STATS) {
        return Err(corrupt("type is not \"collection_stats\""));
    }
    let Value::DateTime(collected_at_ms) = o.req("collected_at")? else {
        return Err(corrupt("collected_at is not a datetime"));
    };
    let fields = o
        .array("fields")?
        .iter()
        .map(decode_field)
        .collect::<Result<Vec<_>, Error>>()?;
    let indexes = o
        .array("indexes")?
        .iter()
        .map(|i| {
            let i = Obj::new(i, INDEX)?;
            Ok(IndexSize {
                index_id: i.id("index_id")?,
                entries: i.count("entries")?,
                bytes: i.count("bytes")?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(CollectionStats {
        database_id: o.id("database_id")?,
        collection_id: o.id("collection_id")?,
        row_count: o.count("row_count")?,
        total_bytes: o.count("total_bytes")?,
        sample_rows: o.count("sample_rows")?,
        collected_at_ms: *collected_at_ms,
        fields,
        indexes,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    type Mutation = Box<dyn Fn(&mut Document)>;

    #[test]
    fn key_layout() {
        assert_eq!(stats_key(0x0102_0304), [0x02, b't', 1, 2, 3, 4]);
    }

    #[test]
    fn strict_decoding() {
        let mut f = FieldStats::new("a", true);
        f.mcv.push(McvEntry {
            value: vec![0x14, 0x80, 0x01, 20],
            fraction: 0.5,
        });
        let s = CollectionStats {
            database_id: 100,
            collection_id: 101,
            row_count: 2,
            total_bytes: 40,
            sample_rows: 2,
            collected_at_ms: 5,
            fields: vec![f],
            indexes: vec![IndexSize {
                index_id: 7,
                entries: 2,
                bytes: 30,
            }],
        };
        let bytes = encode_stats(&s).unwrap();
        assert_eq!(decode_stats(&bytes).unwrap(), s);
        let base = rdoc::decode(&bytes).unwrap();
        let mutate = |f: &dyn Fn(&mut Document)| {
            let mut d = base.clone();
            f(&mut d);
            decode_stats(&rdoc::encode(&d).unwrap())
        };
        let bad: Vec<Mutation> = vec![
            Box::new(|d| {
                d.insert("extra", Value::Null);
            }),
            Box::new(|d| {
                d.insert("stats_format", Value::Int64(2));
            }),
            Box::new(|d| {
                d.insert("row_count", Value::Int64(-1));
            }),
            Box::new(|d| {
                d.insert("type", Value::String("x".into()));
            }),
            Box::new(|d| {
                d.insert("collected_at", Value::Int64(1));
            }),
            Box::new(|d| {
                d.insert("fields", Value::Array(vec![Value::Null]));
            }),
        ];
        for f in &bad {
            let err = mutate(f.as_ref()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::StorageCorruption, "{err}");
        }
        let mut nan = s.clone();
        nan.fields[0].mcv[0].fraction = f64::NAN;
        assert!(encode_stats(&nan).is_err());
        assert!(decode_stats(b"junk").is_err());
    }
}
