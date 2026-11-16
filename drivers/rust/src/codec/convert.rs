// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Conversions from Rust values into [`Value`] and the [`doc!`](crate::doc) macro, so builders
//! and documents take plain Rust values (`42`, `"paid"`, `true`, `vec![...]`).

use super::{Decimal128, Document, ObjectId, Value};

macro_rules! from_int {
    ($($t:ty),*) => {$(
        impl From<$t> for Value {
            fn from(v: $t) -> Self {
                Value::Int64(i64::from(v))
            }
        }
    )*};
}
from_int!(i8, i16, i32, i64, u8, u16, u32);

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Float64(v)
    }
}

impl From<f32> for Value {
    fn from(v: f32) -> Self {
        Value::Float64(f64::from(v))
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_owned())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v)
    }
}

impl From<&String> for Value {
    fn from(v: &String) -> Self {
        Value::String(v.clone())
    }
}

impl From<Decimal128> for Value {
    fn from(v: Decimal128) -> Self {
        Value::Decimal(v)
    }
}

impl From<ObjectId> for Value {
    fn from(v: ObjectId) -> Self {
        Value::ObjectId(v)
    }
}

impl From<Document> for Value {
    fn from(v: Document) -> Self {
        Value::Object(v)
    }
}

impl From<&Value> for Value {
    fn from(v: &Value) -> Self {
        v.clone()
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::Array(v.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map_or(Value::Null, Into::into)
    }
}

impl<K: Into<String>, V: Into<Value>> FromIterator<(K, V)> for Document {
    /// Later fields replace earlier ones with the same name (keeping the first position).
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut d = Document::new();
        for (k, v) in iter {
            d.insert(k, v.into());
        }
        d
    }
}

/// Builds a [`Document`](crate::codec::Document) from `name => value` pairs in order; values are
/// anything that converts into [`Value`](crate::codec::Value).
///
/// ```
/// let d = rustegon::doc! { "_id" => 42, "status" => "paid", "tags" => vec!["a", "b"] };
/// assert_eq!(d.len(), 3);
/// ```
#[macro_export]
macro_rules! doc {
    () => { $crate::codec::Document::new() };
    ($($name:expr => $value:expr),+ $(,)?) => {{
        let mut d = $crate::codec::Document::new();
        $( d.insert($name, $crate::codec::Value::from($value)); )+
        d
    }};
}
