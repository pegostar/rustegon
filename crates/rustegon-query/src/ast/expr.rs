// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Expressions (query-language.md §4) and field paths (§3 `path`).

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use super::literal::Literal;

/// An expression. JSON: an object whose `"kind"` names the variant (§13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expr {
    /// A literal value.
    Literal(Literal),
    /// A parameter: `$name` (named) or `$1` (positional, `name` is the 1-based decimal index).
    Param {
        /// Parameter name or decimal position.
        name: String,
    },
    /// A field path rooted at the current row, e.g. `o.customer.name`, `items[0]`.
    Path {
        /// Segments; the first is always a field.
        path: Path,
    },
    /// Path segments applied to a computed value, e.g. `first(customer).name`.
    /// The base is never a `path` or another `access` (those merge into one path).
    Access {
        /// The value accessed.
        base: Box<Expr>,
        /// Segments applied to it.
        path: Path,
    },
    /// A binary operator.
    Binary {
        /// Operator.
        op: BinaryOp,
        /// Left operand.
        left: Box<Expr>,
        /// Right operand.
        right: Box<Expr>,
    },
    /// `a AND b AND …` (n-ary, at least two operands; keeps long conjunctions shallow).
    And {
        /// Operands, left to right.
        args: Vec<Expr>,
    },
    /// `a OR b OR …` (n-ary, at least two operands).
    Or {
        /// Operands, left to right.
        args: Vec<Expr>,
    },
    /// Unary minus.
    Neg {
        /// Operand.
        expr: Box<Expr>,
    },
    /// `NOT` (binds tighter than comparisons, §4.1).
    Not {
        /// Operand.
        expr: Box<Expr>,
    },
    /// `expr BETWEEN low AND high`.
    Between {
        /// Tested value.
        expr: Box<Expr>,
        /// Inclusive lower bound.
        low: Box<Expr>,
        /// Inclusive upper bound.
        high: Box<Expr>,
    },
    /// `expr IS [NOT] NULL` / `expr IS [NOT] MISSING`.
    Is {
        /// Tested value.
        expr: Box<Expr>,
        /// `IS NOT`.
        #[serde(default, skip_serializing_if = "super::is_false")]
        negated: bool,
        /// What is tested.
        test: IsTest,
    },
    /// Function call `name(args)`; the name is kept as written (binding is case-insensitive).
    Call {
        /// Function name.
        name: String,
        /// Arguments (`count(*)` has a single `star` argument).
        args: Vec<Expr>,
    },
    /// `*` as a function argument (`count(*)`).
    Star,
    /// `extract(unit FROM expr)`.
    Extract {
        /// Date part, e.g. `day`.
        unit: String,
        /// Date value.
        expr: Box<Expr>,
    },
    /// `CASE [operand] WHEN … THEN … [ELSE …] END`.
    Case {
        /// Operand of the simple form `CASE x WHEN v THEN …`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operand: Option<Box<Expr>>,
        /// Branches (at least one).
        whens: Vec<WhenThen>,
        /// `ELSE` value.
        #[serde(rename = "else", default, skip_serializing_if = "Option::is_none")]
        otherwise: Option<Box<Expr>>,
    },
    /// Lambda `x -> body` / `(acc, x) -> body`, argument of higher-order functions.
    Lambda {
        /// Parameter names.
        params: Vec<String>,
        /// Body.
        body: Box<Expr>,
    },
    /// `ANY x IN arr SATISFIES pred` / `EVERY x IN arr SATISFIES pred`.
    Quantified {
        /// `any` or `every`.
        quantifier: Quantifier,
        /// Bound variable.
        var: String,
        /// Array iterated.
        source: Box<Expr>,
        /// Predicate per element.
        predicate: Box<Expr>,
    },
    /// `ELEM MATCH (path, predicate)`: some element of the array at `path` satisfies all of
    /// `predicate` (element-level conjunction).
    ElemMatch {
        /// Array path.
        path: Path,
        /// Element predicate.
        predicate: Box<Expr>,
    },
    /// Array constructor `[a, b]`.
    Array {
        /// Elements.
        elements: Vec<Expr>,
    },
    /// Object constructor `{a: 1, 'b c': 2}`.
    Object {
        /// Fields in order.
        fields: Vec<ObjectField>,
    },
}

/// Binary operators (§4.1). Comparison operators are non-associative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryOp {
    /// `=` (multikey: any array element matches).
    Eq,
    /// `==` (whole-value equality).
    EqWhole,
    /// `!=`.
    Ne,
    /// `<`.
    Lt,
    /// `<=`.
    Le,
    /// `>`.
    Gt,
    /// `>=`.
    Ge,
    /// `IN`.
    In,
    /// `NOT IN`.
    NotIn,
    /// `LIKE`.
    Like,
    /// `ILIKE`.
    Ilike,
    /// `MATCHES` (regular expression).
    Matches,
    /// `CONTAINS`.
    Contains,
    /// `CONTAINS ANY`.
    ContainsAny,
    /// `CONTAINS ALL`.
    ContainsAll,
    /// `+`.
    Add,
    /// `-`.
    Sub,
    /// `*`.
    Mul,
    /// `/`.
    Div,
    /// `%`.
    Mod,
    /// `||` (also written `‖`): string/array concatenation.
    Concat,
}

/// Binding power of prefix `NOT` (§4.1 level 6, PD-033): looser than every comparison and
/// predicate, tighter than `AND` (`OR` is 1 and `AND` 2 in the parser and the printer).
pub(crate) const PREC_NOT: u8 = 3;
/// Precedence level of a binary operator (higher binds tighter; §4.1 levels 5, 4, 3).
pub(crate) const PREC_COMPARISON: u8 = 4;
/// Additive level (`+ - ||`).
pub(crate) const PREC_ADDITIVE: u8 = 5;
/// Multiplicative level (`* / %`).
pub(crate) const PREC_MULTIPLICATIVE: u8 = 6;

impl BinaryOp {
    /// Precedence level (see the `PREC_*` constants).
    #[must_use]
    pub(crate) fn precedence(self) -> u8 {
        match self {
            Self::Add | Self::Sub | Self::Concat => PREC_ADDITIVE,
            Self::Mul | Self::Div | Self::Mod => PREC_MULTIPLICATIVE,
            _ => PREC_COMPARISON,
        }
    }

    /// Canonical spelling.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::EqWhole => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::In => "IN",
            Self::NotIn => "NOT IN",
            Self::Like => "LIKE",
            Self::Ilike => "ILIKE",
            Self::Matches => "MATCHES",
            Self::Contains => "CONTAINS",
            Self::ContainsAny => "CONTAINS ANY",
            Self::ContainsAll => "CONTAINS ALL",
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::Concat => "||",
        }
    }
}

/// What `IS [NOT] …` tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsTest {
    /// `IS NULL`.
    Null,
    /// `IS MISSING`.
    Missing,
}

/// Quantifier of [`Expr::Quantified`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quantifier {
    /// `ANY`.
    Any,
    /// `EVERY`.
    Every,
}

/// A `WHEN … THEN …` branch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhenThen {
    /// Condition (or compared value in the simple form).
    pub when: Expr,
    /// Result.
    pub then: Expr,
}

/// A field of an object constructor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectField {
    /// Field name.
    pub name: String,
    /// Field value.
    pub value: Expr,
}

/// A field path. JSON: an array of segments (see [`Segment`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct Path(pub Vec<Segment>);

impl Path {
    /// A path of plain field names.
    #[must_use]
    pub fn fields<I: IntoIterator<Item = S>, S: Into<String>>(names: I) -> Self {
        Self(
            names
                .into_iter()
                .map(|n| Segment::Field(n.into()))
                .collect(),
        )
    }
}

/// A path segment.
///
/// JSON: a string (field), a non-negative integer (`.0` position), `{"index": <expr>}`
/// (`[expr]`) or `{"each": true}` (`[]`, every array element; only in `INCLUDE` paths).
#[derive(Debug, Clone, PartialEq)]
pub enum Segment {
    /// `.name` (or the root name).
    Field(String),
    /// `.0`: array position written with a dot.
    Position(u32),
    /// `[expr]`.
    Index(Box<Expr>),
    /// `[]`: every element (`INCLUDE items[].productId`).
    Each,
}

impl Serialize for Segment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Self::Field(name) => serializer.serialize_str(name),
            Self::Position(p) => serializer.serialize_u32(*p),
            Self::Index(expr) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("index", expr)?;
                map.end()
            }
            Self::Each => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("each", &true)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Segment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bad = || {
            D::Error::custom(
                "path segment must be a string, an integer, {\"index\":…} or {\"each\":true}",
            )
        };
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(s) => Ok(Self::Field(s)),
            serde_json::Value::Number(n) => n
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .map(Self::Position)
                .ok_or_else(bad),
            serde_json::Value::Object(mut map) if map.len() == 1 => {
                if let Some(index) = map.remove("index") {
                    serde_json::from_value(index)
                        .map(|e| Self::Index(Box::new(e)))
                        .map_err(D::Error::custom)
                } else if map.get("each") == Some(&serde_json::Value::Bool(true)) {
                    Ok(Self::Each)
                } else {
                    Err(bad())
                }
            }
            _ => Err(bad()),
        }
    }
}
