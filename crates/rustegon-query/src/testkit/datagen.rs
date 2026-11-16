// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Seeded generators of documents and expressions.
//!
//! The vocabulary is deliberately small (a few field names, values and strings) so that
//! predicates hit real data, while every value class of data-model §2.1 that matters to M3 is
//! present: `missing` vs `null`, `int64`/`float64`/`decimal128` with equal values (`1`, `1.0`,
//! `1.00m`), `-0.0` and NaN, strings with `LIKE` metacharacters, nested objects, arrays of
//! scalars, of objects and of mixed elements, booleans and datetimes.

use rustegon_doc::{Decimal128, Document, Value};

use super::{Params, rng::Rng};
use crate::ast::{
    BinaryOp, Expr, IsTest, Literal, ObjectField, Path, Quantifier, Segment, WhenThen,
};

/// Generator options.
#[derive(Debug, Clone)]
pub struct GenConfig {
    /// Documents per collection: `0..=max_docs`.
    pub max_docs: usize,
    /// Statements per case.
    pub steps: usize,
    /// Maximum expression nesting.
    pub max_depth: usize,
    /// Allow `now()` / `CURRENT DATE` (needs an engine whose clock is fixed, see
    /// [`super::QueryEngine`]).
    pub time_dependent: bool,
    /// Percentage of write statements among the steps.
    pub write_percent: usize,
}

impl Default for GenConfig {
    fn default() -> Self {
        Self {
            max_docs: 12,
            steps: 8,
            max_depth: 3,
            time_dependent: false,
            write_percent: 35,
        }
    }
}

/// Strings, including `LIKE` metacharacters and case variants.
pub const STRINGS: &[&str] = &[
    "", "a", "ab", "abc", "B", "ba", "a_c", "100%", "x y", "s1", "s2",
];
/// Paths that the expression generator reads.
pub const PATHS: &[&str] = &[
    "a",
    "b",
    "c",
    "c.x",
    "c.y.z",
    "tags",
    "tags.0",
    "items",
    "items.sku",
    "items.qty",
    "flag",
    "n",
    "_id",
    "nope",
];
/// `LIKE` patterns.
pub const LIKE_PATTERNS: &[&str] = &["a%", "%b", "_", "a_c", "%", "A%", "100\\%", "%c%", ""];
/// `MATCHES` patterns.
pub const REGEXES: &[&str] = &["^a", "c$", "[0-9]", "^$", "a.c", "(?i)^b"];
/// Decimal literals, with cohort members of the same value.
const DECIMALS: &[&str] = &["1", "1.00", "-2.50", "0", "3", "0.5"];
/// Floats, including `-0.0` and NaN (written only into data, never as literals).
const FLOATS: &[f64] = &[-1.5, 0.0, -0.0, 0.5, 1.0, 2.0, 2.5, f64::NAN];

/// A random scalar of any M3 class (no `missing`).
pub fn scalar(rng: &mut Rng, literal: bool) -> Value {
    match rng.below(9) {
        0 => Value::Null,
        1 => Value::Bool(rng.chance(50)),
        2 | 3 => Value::Int64(rng.range(-3, 3)),
        4 => {
            let f = *rng.pick(FLOATS);
            // NaN has no literal syntax.
            Value::Float64(if literal && f.is_nan() { 1.5 } else { f })
        }
        5 => {
            Value::Decimal(Decimal128::parse(rng.pick(DECIMALS)).unwrap_or(Decimal128::from_i64(1)))
        }
        6 if !literal => Value::DateTime(1_767_225_600_000 + rng.range(-2, 2) * 86_400_000),
        _ => Value::String((*rng.pick(STRINGS)).to_owned()),
    }
}

fn small_array(rng: &mut Rng) -> Value {
    let n = rng.below(4);
    Value::Array(
        (0..n)
            .map(|_| match rng.below(6) {
                0 => Value::Null,
                1 => Value::Int64(rng.range(0, 2)),
                _ => Value::String((*rng.pick(&["a", "b", "c"])).to_owned()),
            })
            .collect(),
    )
}

fn item(rng: &mut Rng) -> Value {
    if rng.chance(10) {
        return Value::Int64(7);
    }
    let mut d = Document::new();
    d.insert(
        "sku",
        Value::String((*rng.pick(&["s1", "s2", "s3"])).to_owned()),
    );
    if rng.chance(85) {
        d.insert("qty", Value::Int64(rng.range(0, 5)));
    }
    Value::Object(d)
}

/// One document with `_id` = `id`; every other field may be absent.
pub fn document(rng: &mut Rng, id: Value) -> Document {
    let mut d = Document::new();
    d.insert("_id", id);
    if rng.chance(85) {
        d.insert("a", scalar(rng, false));
    }
    if rng.chance(80) {
        let b = if rng.chance(85) {
            Value::String((*rng.pick(STRINGS)).to_owned())
        } else {
            scalar(rng, false)
        };
        d.insert("b", b);
    }
    if rng.chance(70) {
        let c = if rng.chance(75) {
            let mut c = Document::new();
            if rng.chance(80) {
                c.insert("x", scalar(rng, false));
            }
            let mut y = Document::new();
            y.insert("z", Value::Int64(rng.range(-1, 2)));
            c.insert("y", Value::Object(y));
            Value::Object(c)
        } else {
            scalar(rng, false)
        };
        d.insert("c", c);
    }
    if rng.chance(75) {
        let tags = if rng.chance(85) {
            small_array(rng)
        } else {
            scalar(rng, false)
        };
        d.insert("tags", tags);
    }
    if rng.chance(60) {
        let n = rng.below(4);
        d.insert("items", Value::Array((0..n).map(|_| item(rng)).collect()));
    }
    if rng.chance(70) {
        let flag = match rng.below(4) {
            0 => Value::Null,
            1 => Value::Int64(1),
            _ => Value::Bool(rng.chance(50)),
        };
        d.insert("flag", flag);
    }
    if rng.chance(90) {
        d.insert("n", Value::Int64(rng.range(-5, 5)));
    }
    d
}

/// `0..=max` documents with distinct `_id`s (mostly integers, some strings).
pub fn documents(rng: &mut Rng, max: usize) -> Vec<Document> {
    let n = rng.below(max + 1);
    (0..n)
        .map(|i| {
            let i = i64::try_from(i).unwrap_or(0);
            let id = if rng.chance(15) {
                Value::String(format!("k{i}"))
            } else {
                Value::Int64(i)
            };
            document(rng, id)
        })
        .collect()
}

/// A literal expression of a value (arrays and objects become constructors).
#[must_use]
pub fn literal(v: &Value) -> Expr {
    match v {
        Value::Bool(b) => Expr::Literal(Literal::Bool(*b)),
        Value::Int64(i) => Expr::Literal(Literal::Int(*i)),
        Value::Float64(f) => Expr::Literal(Literal::Float(*f)),
        Value::Decimal(d) => Expr::Literal(Literal::Decimal(*d)),
        Value::DateTime(ms) => Expr::Literal(Literal::DateTime(*ms)),
        Value::Array(items) => Expr::Array {
            elements: items.iter().map(literal).collect(),
        },
        Value::Object(d) => Expr::Object {
            fields: d
                .iter()
                .map(|(k, v)| ObjectField {
                    name: k.to_owned(),
                    value: literal(v),
                })
                .collect(),
        },
        Value::String(s) => Expr::Literal(Literal::String(s.clone())),
        // `null`, and the classes the generator never produces.
        _ => Expr::Literal(Literal::Null),
    }
}

/// A dotted path; numeric segments are positions.
#[must_use]
pub fn path(dotted: &str) -> Path {
    Path(
        dotted
            .split('.')
            .map(|s| match s.parse::<u32>() {
                Ok(p) => Segment::Position(p),
                Err(_) => Segment::Field(s.to_owned()),
            })
            .collect(),
    )
}

fn call(name: &str, args: Vec<Expr>) -> Expr {
    Expr::Call {
        name: name.to_owned(),
        args,
    }
}

fn bin(op: BinaryOp, l: Expr, r: Expr) -> Expr {
    Expr::Binary {
        op,
        left: Box::new(l),
        right: Box::new(r),
    }
}

fn lit_str(s: &str) -> Expr {
    Expr::Literal(Literal::String(s.to_owned()))
}

fn lit_int(i: i64) -> Expr {
    Expr::Literal(Literal::Int(i))
}

/// Expression generator state for one statement.
#[derive(Debug)]
pub struct ExprGen<'r> {
    /// Random stream.
    pub rng: &'r mut Rng,
    /// `FROM … AS alias` in effect (paths are prefixed with it at random).
    pub alias: Option<String>,
    /// Parameters bound so far.
    pub params: Params,
    /// Options.
    pub config: GenConfig,
}

impl ExprGen<'_> {
    /// A path expression over the document vocabulary.
    pub fn path_expr(&mut self) -> Expr {
        let mut p = path(self.rng.pick(PATHS));
        if let Some(a) = &self.alias
            && self.rng.chance(50)
        {
            p.0.insert(0, Segment::Field(a.clone()));
        }
        Expr::Path { path: p }
    }

    /// A constant: a literal or a fresh parameter.
    pub fn constant(&mut self) -> Expr {
        let v = if self.rng.chance(15) {
            small_array(self.rng)
        } else {
            scalar(self.rng, true)
        };
        if self.rng.chance(20) {
            let name = format!("p{}", self.params.len() + 1);
            self.params.insert(name.clone(), v);
            Expr::Param { name }
        } else {
            literal(&v)
        }
    }

    /// A value-producing expression.
    pub fn scalar(&mut self, depth: usize) -> Expr {
        let choice = if depth == 0 {
            self.rng.below(3)
        } else {
            self.rng.below(9)
        };
        match choice {
            0 | 1 => self.path_expr(),
            2 => self.constant(),
            3 => {
                let op = *self.rng.pick(&[
                    BinaryOp::Add,
                    BinaryOp::Sub,
                    BinaryOp::Mul,
                    BinaryOp::Div,
                    BinaryOp::Mod,
                    BinaryOp::Concat,
                ]);
                let l = self.scalar(depth - 1);
                let r = self.scalar(depth - 1);
                bin(op, l, r)
            }
            4 => Expr::Neg {
                expr: Box::new(self.path_expr()),
            },
            5 | 6 => self.function(depth - 1),
            7 => Expr::Case {
                operand: None,
                whens: vec![WhenThen {
                    when: self.predicate(depth - 1),
                    then: self.scalar(depth - 1),
                }],
                otherwise: self
                    .rng
                    .chance(70)
                    .then(|| Box::new(self.scalar(depth - 1))),
            },
            _ => Expr::Array {
                elements: vec![self.scalar(depth - 1), self.constant()],
            },
        }
    }

    fn function(&mut self, depth: usize) -> Expr {
        let p = |s: &str| Expr::Path { path: path(s) };
        let arg = self.scalar(depth);
        match self.rng.below(24) {
            0 => call("lower", vec![p("b")]),
            1 => call("upper", vec![arg]),
            2 => call("length", vec![p("b")]),
            3 => call("abs", vec![arg]),
            4 => call("size", vec![p("tags")]),
            5 => call("coalesce", vec![p("a"), arg]),
            6 => call("if_null", vec![p("c.x"), arg]),
            7 => call("type_of", vec![arg]),
            8 => call("to_string", vec![arg]),
            9 => call("concat", vec![p("b"), lit_str("x")]),
            10 => call(
                "substr",
                vec![p("b"), lit_int(self.rng.range(0, 2)), lit_int(2)],
            ),
            11 => call(
                self.rng.pick(&["round", "floor", "ceil", "trunc"]),
                vec![arg],
            ),
            12 => call(self.rng.pick(&["greatest", "least"]), vec![arg, lit_int(0)]),
            13 => call(self.rng.pick(&["first", "last"]), vec![p("tags")]),
            14 => call(self.rng.pick(&["to_int", "to_float", "to_bool"]), vec![arg]),
            15 => call("array_distinct", vec![p("tags")]),
            16 => call(
                "filter",
                vec![
                    p("tags"),
                    Expr::Lambda {
                        params: vec!["t".into()],
                        body: Box::new(bin(BinaryOp::Ne, p("t"), self.constant())),
                    },
                ],
            ),
            17 => call(
                "map",
                vec![
                    p("items"),
                    Expr::Lambda {
                        params: vec!["i".into()],
                        body: Box::new(p("i.qty")),
                    },
                ],
            ),
            18 => call("replace", vec![p("b"), lit_str("a"), lit_str("z")]),
            19 => call("index_of", vec![p("b"), lit_str("b")]),
            20 => call("mod", vec![arg, lit_int(2)]),
            21 => call("if", vec![self.predicate(depth), arg, lit_int(-1)]),
            22 if self.config.time_dependent => call("now", vec![]),
            _ => call("trim", vec![arg]),
        }
    }

    /// A boolean-or-unknown expression (never `missing`, never another type), so that TLP's
    /// three partitions `p`, `NOT p`, `p IS NULL` cover every row.
    // One arm per predicate form of �4.1: a flat table keeps the grammar coverage auditable.
    #[allow(clippy::too_many_lines)]
    pub fn predicate(&mut self, depth: usize) -> Expr {
        let n = if depth == 0 { 14 } else { 17 };
        match self.rng.below(n) {
            0..=3 => {
                let op = *self.rng.pick(&[
                    BinaryOp::Eq,
                    BinaryOp::Ne,
                    BinaryOp::Lt,
                    BinaryOp::Le,
                    BinaryOp::Gt,
                    BinaryOp::Ge,
                    BinaryOp::EqWhole,
                ]);
                let l = self.scalar(depth.saturating_sub(1));
                let r = if self.rng.chance(60) {
                    self.constant()
                } else {
                    self.path_expr()
                };
                bin(op, l, r)
            }
            4 => {
                let op = if self.rng.chance(70) {
                    BinaryOp::In
                } else {
                    BinaryOp::NotIn
                };
                let list = if self.rng.chance(80) {
                    small_array(self.rng)
                } else {
                    Value::Array(vec![scalar(self.rng, true), scalar(self.rng, true)])
                };
                bin(op, self.path_expr(), literal(&list))
            }
            5 => Expr::Between {
                expr: Box::new(self.path_expr()),
                low: Box::new(self.constant()),
                high: Box::new(self.constant()),
            },
            6 => {
                let op = *self.rng.pick(&[BinaryOp::Like, BinaryOp::Ilike]);
                let target = Expr::Path {
                    path: path(self.rng.pick(&["b", "tags", "a"])),
                };
                bin(op, target, lit_str(self.rng.pick(LIKE_PATTERNS)))
            }
            7 => bin(
                BinaryOp::Matches,
                Expr::Path { path: path("b") },
                lit_str(self.rng.pick(REGEXES)),
            ),
            8 => Expr::Is {
                expr: Box::new(self.scalar(depth.saturating_sub(1))),
                negated: self.rng.chance(40),
                test: if self.rng.chance(50) {
                    IsTest::Null
                } else {
                    IsTest::Missing
                },
            },
            9 => {
                let op = *self.rng.pick(&[
                    BinaryOp::Contains,
                    BinaryOp::ContainsAny,
                    BinaryOp::ContainsAll,
                ]);
                let rhs = if op == BinaryOp::Contains {
                    literal(&Value::String(
                        (*self.rng.pick(&["a", "b", "c"])).to_owned(),
                    ))
                } else {
                    literal(&small_array(self.rng))
                };
                bin(
                    op,
                    Expr::Path {
                        path: path(self.rng.pick(&["tags", "b"])),
                    },
                    rhs,
                )
            }
            10 => {
                let (var, source, body) = if self.rng.chance(50) {
                    (
                        "t",
                        "tags",
                        bin(
                            BinaryOp::Eq,
                            Expr::Path { path: path("t") },
                            self.constant(),
                        ),
                    )
                } else {
                    let l = Expr::Path {
                        path: path("i.qty"),
                    };
                    (
                        "i",
                        "items",
                        bin(BinaryOp::Gt, l, lit_int(self.rng.range(0, 4))),
                    )
                };
                Expr::Quantified {
                    quantifier: if self.rng.chance(50) {
                        Quantifier::Any
                    } else {
                        Quantifier::Every
                    },
                    var: var.into(),
                    source: Box::new(Expr::Path { path: path(source) }),
                    predicate: Box::new(body),
                }
            }
            11 => Expr::ElemMatch {
                path: path("items"),
                predicate: Box::new(Expr::And {
                    args: vec![
                        bin(
                            BinaryOp::Ge,
                            Expr::Path { path: path("qty") },
                            lit_int(self.rng.range(0, 4)),
                        ),
                        bin(
                            BinaryOp::Eq,
                            Expr::Path { path: path("sku") },
                            lit_str(self.rng.pick(&["s1", "s2"])),
                        ),
                    ],
                }),
            },
            12 => {
                let p = |s: &str| Expr::Path { path: path(s) };
                match self.rng.below(5) {
                    0 => call("starts_with", vec![p("b"), lit_str(self.rng.pick(STRINGS))]),
                    1 => call("ends_with", vec![p("b"), lit_str("c")]),
                    2 => call("array_contains", vec![p("tags"), lit_str("a")]),
                    3 => call(
                        self.rng.pick(&["is_number", "is_string"]),
                        vec![self.path_expr()],
                    ),
                    _ => call("regex_match", vec![p("b"), lit_str(self.rng.pick(REGEXES))]),
                }
            }
            13 => Expr::Literal(match self.rng.below(3) {
                0 => Literal::Bool(true),
                1 => Literal::Bool(false),
                _ => Literal::Null,
            }),
            14 => Expr::Not {
                expr: Box::new(self.predicate(depth - 1)),
            },
            15 => Expr::And {
                args: (0..self.rng.range(2, 3))
                    .map(|_| self.predicate(depth - 1))
                    .collect(),
            },
            _ => Expr::Or {
                args: (0..self.rng.range(2, 3))
                    .map(|_| self.predicate(depth - 1))
                    .collect(),
            },
        }
    }
}
