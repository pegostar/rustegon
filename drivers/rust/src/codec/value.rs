// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The in-memory value model (data-model.md §2, FR-DOC-001).
//!
//! The codec modules are a copy of the server's `rustegon-doc` (PD-180: the driver depends on no
//! server crate); the shared vectors of `drivers/conformance/codec/` keep both byte-identical.
//!
//! `PartialEq`/`Eq` on [`Value`] are *representational* identity (same type, same bits; all NaNs
//! equal; `1 != 1.0`; `-0.0 != 0.0`); the server compares `1 = 1.0` in queries.

use crate::codec::{
    decimal::Decimal128,
    error::{DocError, DocResult},
    oid::ObjectId,
};

/// Binary subtype 0: generic bytes.
pub const BINARY_GENERIC: u8 = 0x00;
/// Binary subtype 4: UUID (exactly 16 bytes).
pub const BINARY_UUID: u8 = 0x04;
/// First user-defined binary subtype (0x80..=0xFF).
pub const BINARY_USER_MIN: u8 = 0x80;

/// Hybrid logical clock timestamp (type `timestamp`, 12 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Timestamp {
    /// Wall-clock component (physical time, units defined by the HLC).
    pub wall: u64,
    /// Logical counter.
    pub logical: u32,
}

/// A typed value of the document model (data-model.md §2). See the module docs for `missing`.
#[derive(Debug, Clone)]
pub enum Value {
    /// `null` (0x01).
    Null,
    /// `bool` (0x02).
    Bool(bool),
    /// `int64` (0x03).
    Int64(i64),
    /// `float64` (0x04).
    Float64(f64),
    /// `decimal128` (0x05).
    Decimal(Decimal128),
    /// `string` (0x06), UTF-8, NUL allowed.
    String(String),
    /// `binary` (0x07): subtype 0, 4 (16-byte UUID) or 0x80..=0xFF.
    Binary {
        /// Subtype byte.
        subtype: u8,
        /// Payload.
        data: Vec<u8>,
    },
    /// `datetime` (0x08): milliseconds since the Unix epoch, UTC.
    DateTime(i64),
    /// `timestamp` (0x09).
    Timestamp(Timestamp),
    /// `objectId` (0x0A).
    ObjectId(ObjectId),
    /// `uuid` (0x0B).
    Uuid([u8; 16]),
    /// `array` (0x0C).
    Array(Vec<Value>),
    /// `object` (0x0D), field order preserved.
    Object(Document),
    /// `vector_f32` (0x0E); elements are finite.
    VectorF32(Vec<f32>),
    /// `counter` (0x0F): read-only projection of a document counter, never accepted as input
    /// and not key-encodable.
    Counter(i64),
    /// `minKey` (0x10).
    MinKey,
    /// `maxKey` (0x11).
    MaxKey,
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        use Value as V;
        match (self, other) {
            (V::Null, V::Null) | (V::MinKey, V::MinKey) | (V::MaxKey, V::MaxKey) => true,
            (V::Bool(a), V::Bool(b)) => a == b,
            (V::Int64(a), V::Int64(b))
            | (V::DateTime(a), V::DateTime(b))
            | (V::Counter(a), V::Counter(b)) => a == b,
            (V::Float64(a), V::Float64(b)) => {
                (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
            }
            (V::Decimal(a), V::Decimal(b)) => a == b,
            (V::String(a), V::String(b)) => a == b,
            (
                V::Binary {
                    subtype: sa,
                    data: da,
                },
                V::Binary {
                    subtype: sb,
                    data: db,
                },
            ) => sa == sb && da == db,
            (V::Timestamp(a), V::Timestamp(b)) => a == b,
            (V::ObjectId(a), V::ObjectId(b)) => a == b,
            (V::Uuid(a), V::Uuid(b)) => a == b,
            (V::Array(a), V::Array(b)) => a == b,
            (V::Object(a), V::Object(b)) => a == b,
            (V::VectorF32(a), V::VectorF32(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_bits() == y.to_bits())
            }
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Value {
    /// The type tag of data-model.md §2 (also the `RDoc` tag byte).
    #[must_use]
    pub fn type_tag(&self) -> u8 {
        match self {
            Self::Null => 0x01,
            Self::Bool(_) => 0x02,
            Self::Int64(_) => 0x03,
            Self::Float64(_) => 0x04,
            Self::Decimal(_) => 0x05,
            Self::String(_) => 0x06,
            Self::Binary { .. } => 0x07,
            Self::DateTime(_) => 0x08,
            Self::Timestamp(_) => 0x09,
            Self::ObjectId(_) => 0x0A,
            Self::Uuid(_) => 0x0B,
            Self::Array(_) => 0x0C,
            Self::Object(_) => 0x0D,
            Self::VectorF32(_) => 0x0E,
            Self::Counter(_) => 0x0F,
            Self::MinKey => 0x10,
            Self::MaxKey => 0x11,
        }
    }
}

/// An object: ordered field/value pairs with unique names (FR-DOC-001).
///
/// Insertion order is preserved (data-model.md §2, `RDoc` stores fields in insertion order).
/// Uniqueness is the only invariant enforced here; field-name syntax (§2.2) is checked by the
/// parsers and encoders, which know whether they handle user input or stored data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Document {
    fields: Vec<(String, Value)>,
}

impl Document {
    /// An empty object.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds an object from fields in insertion order.
    ///
    /// # Errors
    /// [`DocError::InvalidFieldName`] (`RGN-1004`) if a name occurs twice.
    pub fn try_from_fields(fields: Vec<(String, Value)>) -> DocResult<Self> {
        // Small objects dominate: a quadratic scan beats hashing below ~16 fields.
        const LINEAR_SCAN_MAX: usize = 16;
        let duplicate = if fields.len() <= LINEAR_SCAN_MAX {
            fields
                .iter()
                .enumerate()
                .any(|(i, (a, _))| fields[..i].iter().any(|(b, _)| a == b))
        } else {
            let mut names: Vec<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
            names.sort_unstable();
            names.windows(2).any(|w| w[0] == w[1])
        };
        if duplicate {
            return Err(DocError::InvalidFieldName("duplicate field name".into()));
        }
        Ok(Self { fields })
    }

    /// Wraps fields already known to have unique names (decoders that proved it).
    pub(crate) fn from_unique_fields(fields: Vec<(String, Value)>) -> Self {
        Self { fields }
    }

    /// Sets `name` to `value`: replaces the value in place if the field exists (keeping its
    /// position), appends otherwise. Returns the previous value.
    pub fn insert(&mut self, name: impl Into<String>, value: Value) -> Option<Value> {
        let name = name.into();
        if let Some(slot) = self.fields.iter_mut().find(|(n, _)| *n == name) {
            return Some(std::mem::replace(&mut slot.1, value));
        }
        self.fields.push((name, value));
        None
    }

    /// The value of field `name`, if present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// The value of field `name`, mutably, if present.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Value> {
        self.fields
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    }

    /// Removes field `name`, keeping the order of the remaining fields; returns its value.
    pub fn remove(&mut self, name: &str) -> Option<Value> {
        let at = self.fields.iter().position(|(n, _)| n == name)?;
        Some(self.fields.remove(at).1)
    }

    /// Fields in insertion order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &Value)> {
        self.fields.iter().map(|(n, v)| (n.as_str(), v))
    }

    /// Number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// `true` when there are no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The fields in insertion order.
    #[must_use]
    pub fn into_fields(self) -> Vec<(String, Value)> {
        self.fields
    }

    /// The fields in insertion order, borrowed.
    #[must_use]
    pub fn fields(&self) -> &[(String, Value)] {
        &self.fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_duplicate_names_rejected_small_and_large() {
        let small = vec![("a".into(), Value::Null), ("a".into(), Value::Null)];
        assert!(Document::try_from_fields(small).is_err());
        let mut large: Vec<(String, Value)> =
            (0..40).map(|i| (format!("f{i}"), Value::Null)).collect();
        assert!(Document::try_from_fields(large.clone()).is_ok());
        large.push(("f7".into(), Value::Null));
        assert!(Document::try_from_fields(large).is_err());
    }

    #[test]
    fn document_insert_keeps_position() {
        let mut d = Document::new();
        d.insert("a", Value::Int64(1));
        d.insert("b", Value::Int64(2));
        assert_eq!(d.insert("a", Value::Int64(3)), Some(Value::Int64(1)));
        let names: Vec<&str> = d.iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["a", "b"]);
    }

    #[test]
    fn value_eq_is_representational() {
        assert_eq!(Value::Float64(f64::NAN), Value::Float64(-f64::NAN));
        assert_ne!(Value::Float64(0.0), Value::Float64(-0.0));
        assert_ne!(Value::Int64(1), Value::Float64(1.0));
    }
}
