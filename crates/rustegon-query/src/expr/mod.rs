// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Bound expressions and the engine's expression evaluator (query-language.md §4).
//!
//! The binder lowers AST [`Expr`](crate::ast::Expr)s into [`BExpr`]: names resolved (row alias
//! stripped, lambda and quantifier variables turned into slots), parameters substituted as
//! constants, functions resolved to [`Func`]. The evaluator ([`eval()`](fn@eval)) works on `Option<Value>`
//! where `None` is `missing` (data-model.md §2; `missing` is not a stored value).
//!
//! This evaluator is deliberately independent of the reference interpreter
//! (`rustegon-query::reference`, differential testing): no evaluation code is shared.

pub mod catalog;
pub mod eval;
pub mod func;
mod func_array;
pub mod func_date;
mod func_string;
pub mod ops;
pub mod print;

use std::sync::Arc;

use regex::Regex;
use rustegon_doc::Value;

pub use self::{
    catalog::{Func, FuncClass, lookup_function},
    eval::{EvalCtx, Scope, eval, eval_predicate},
};

/// A value or `missing` (`None`).
pub type Val = Option<Value>;

/// One step of a path: a field (with its array index when the segment is a canonical decimal
/// number written `.0`) or a computed `[expr]`.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// `.name` (`index` is `Some` for `.0`: an element on arrays, the field `"0"` on objects).
    Field {
        /// Field name (decimal text for positions).
        name: String,
        /// Array position for numeric segments.
        index: Option<usize>,
    },
    /// `[expr]`: an integer selects an array element, a string an object field.
    Dyn(Box<BExpr>),
}

impl Step {
    /// A plain field step.
    #[must_use]
    pub fn field(name: impl Into<String>) -> Self {
        Self::Field {
            name: name.into(),
            index: None,
        }
    }
}

/// Comparison operators (§4.1 level 5, minus the pattern and membership operators).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    /// `=` (multikey: any element of an array left operand).
    Eq,
    /// `==` (whole values).
    EqWhole,
    /// `!=` (defined as `NOT (=)`, so `tags != 'x'` means no element equals `'x'`).
    Ne,
    /// `<`.
    Lt,
    /// `<=`.
    Le,
    /// `>`.
    Gt,
    /// `>=`.
    Ge,
}

impl CmpOp {
    /// The operator with its operands swapped (`a < b` ⇔ `b > a`).
    #[must_use]
    pub fn flipped(self) -> Self {
        match self {
            Self::Lt => Self::Gt,
            Self::Le => Self::Ge,
            Self::Gt => Self::Lt,
            Self::Ge => Self::Le,
            other => other,
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
        }
    }
}

/// Arithmetic and concatenation operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
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
    /// `||`.
    Concat,
}

impl ArithOp {
    /// Canonical spelling.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::Concat => "||",
        }
    }
}

/// `CONTAINS`, `CONTAINS ANY`, `CONTAINS ALL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainsMode {
    /// One value (or a substring of a string).
    One,
    /// At least one of the array's elements.
    Any,
    /// Every element of the array.
    All,
}

/// `IS NULL` / `IS MISSING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsKind {
    /// Matches `null` and `missing` (data-model §2.1).
    Null,
    /// Matches `missing` only.
    Missing,
}

/// A compiled regular expression shared by the plan (compiled once at bind time when the
/// pattern is a constant).
#[derive(Debug, Clone)]
pub struct CompiledRegex(pub Arc<Regex>);

impl PartialEq for CompiledRegex {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

/// A bound expression (module docs).
#[derive(Debug, Clone, PartialEq)]
pub enum BExpr {
    /// A constant (`None` = missing).
    Const(Val),
    /// A path from the current row; no steps = the row itself.
    Field(Vec<Step>),
    /// A variable (lambda parameter, quantifier or element variable) with steps applied.
    Var {
        /// Slot in the scope's variable stack.
        slot: usize,
        /// Display name.
        name: String,
        /// Steps applied to the variable's value.
        steps: Vec<Step>,
    },
    /// Steps applied to a computed value.
    Access {
        /// Base value.
        base: Box<BExpr>,
        /// Steps.
        steps: Vec<Step>,
    },
    /// Comparison.
    Cmp {
        /// Operator.
        op: CmpOp,
        /// Left operand (multikey side).
        left: Box<BExpr>,
        /// Right operand.
        right: Box<BExpr>,
    },
    /// Arithmetic or concatenation.
    Arith {
        /// Operator.
        op: ArithOp,
        /// Left operand.
        left: Box<BExpr>,
        /// Right operand.
        right: Box<BExpr>,
    },
    /// Conjunction (three-valued).
    And(Vec<BExpr>),
    /// Disjunction (three-valued).
    Or(Vec<BExpr>),
    /// Negation (three-valued).
    Not(Box<BExpr>),
    /// Unary minus.
    Neg(Box<BExpr>),
    /// `expr [NOT] IN list`.
    In {
        /// Tested value (multikey).
        expr: Box<BExpr>,
        /// Array of candidates.
        list: Box<BExpr>,
        /// `NOT IN`.
        negated: bool,
    },
    /// `expr LIKE pattern` / `ILIKE`.
    Like {
        /// Tested value (multikey).
        expr: Box<BExpr>,
        /// Pattern (`%`, `_`, `\` escape).
        pattern: Box<BExpr>,
        /// `ILIKE`.
        case_insensitive: bool,
    },
    /// `expr MATCHES regex`.
    Matches {
        /// Tested value (multikey).
        expr: Box<BExpr>,
        /// Pattern expression.
        pattern: Box<BExpr>,
        /// Pre-compiled pattern when it is a constant.
        compiled: Option<CompiledRegex>,
    },
    /// `CONTAINS [ANY|ALL]`.
    Contains {
        /// Array or string.
        expr: Box<BExpr>,
        /// Value or array of values.
        arg: Box<BExpr>,
        /// Mode.
        mode: ContainsMode,
    },
    /// `IS [NOT] NULL|MISSING` (never unknown).
    Is {
        /// Tested value (whole value, no multikey).
        expr: Box<BExpr>,
        /// Test.
        kind: IsKind,
        /// `IS NOT`.
        negated: bool,
    },
    /// Scalar function call.
    Call {
        /// Function.
        func: Func,
        /// Arguments (lambdas as [`BExpr::Lambda`]).
        args: Vec<BExpr>,
    },
    /// `CASE`.
    Case {
        /// Operand of the simple form.
        operand: Option<Box<BExpr>>,
        /// `(when, then)` branches.
        whens: Vec<(BExpr, BExpr)>,
        /// `ELSE` (`null` when absent).
        otherwise: Option<Box<BExpr>>,
    },
    /// A lambda (only as a higher-order function argument): parameters occupy the slots
    /// `first_slot..first_slot + arity`.
    Lambda {
        /// First parameter slot.
        first_slot: usize,
        /// Parameter names.
        params: Vec<String>,
        /// Body.
        body: Box<BExpr>,
    },
    /// `ANY|EVERY var IN source SATISFIES predicate`.
    Quantified {
        /// `EVERY` (else `ANY`).
        every: bool,
        /// Slot of the variable.
        slot: usize,
        /// Variable name.
        var: String,
        /// Array iterated.
        source: Box<BExpr>,
        /// Predicate.
        predicate: Box<BExpr>,
    },
    /// `ELEM MATCH (path, predicate)`: some element satisfies the predicate; inside it, paths
    /// are relative to the element (slot `slot`).
    ElemMatch {
        /// Array.
        source: Box<BExpr>,
        /// Element slot.
        slot: usize,
        /// Predicate.
        predicate: Box<BExpr>,
    },
    /// Array constructor.
    Array(Vec<BExpr>),
    /// Object constructor (a `missing` value omits the field).
    Object(Vec<(String, BExpr)>),
}

impl BExpr {
    /// `Const(Some(v))`.
    #[must_use]
    pub fn value(v: Value) -> Self {
        Self::Const(Some(v))
    }

    /// The constant `null`.
    #[must_use]
    pub fn null() -> Self {
        Self::Const(Some(Value::Null))
    }

    /// Whether this is a constant.
    #[must_use]
    pub fn is_const(&self) -> bool {
        matches!(self, Self::Const(_))
    }

    /// The static field path of a `Field` expression without computed steps.
    #[must_use]
    pub fn static_path(&self) -> Option<&[Step]> {
        match self {
            Self::Field(steps)
                if !steps.is_empty() && steps.iter().all(|s| !matches!(s, Step::Dyn(_))) =>
            {
                Some(steps)
            }
            _ => None,
        }
    }

    /// Visits this expression and every sub-expression (pre-order).
    pub fn walk(&self, f: &mut dyn FnMut(&BExpr)) {
        f(self);
        let walk_steps = |steps: &[Step], f: &mut dyn FnMut(&BExpr)| {
            for s in steps {
                if let Step::Dyn(e) = s {
                    e.walk(f);
                }
            }
        };
        match self {
            Self::Const(_) => {}
            Self::Field(steps) | Self::Var { steps, .. } => walk_steps(steps, f),
            Self::Access { base, steps } => {
                base.walk(f);
                walk_steps(steps, f);
            }
            Self::Cmp { left, right, .. } | Self::Arith { left, right, .. } => {
                left.walk(f);
                right.walk(f);
            }
            Self::And(v) | Self::Or(v) | Self::Array(v) | Self::Call { args: v, .. } => {
                for e in v {
                    e.walk(f);
                }
            }
            Self::Not(e)
            | Self::Neg(e)
            | Self::Is { expr: e, .. }
            | Self::Lambda { body: e, .. } => {
                e.walk(f);
            }
            Self::In {
                expr, list: other, ..
            }
            | Self::Like {
                expr,
                pattern: other,
                ..
            }
            | Self::Matches {
                expr,
                pattern: other,
                ..
            }
            | Self::Contains {
                expr, arg: other, ..
            }
            | Self::Quantified {
                source: expr,
                predicate: other,
                ..
            }
            | Self::ElemMatch {
                source: expr,
                predicate: other,
                ..
            } => {
                expr.walk(f);
                other.walk(f);
            }
            Self::Case {
                operand,
                whens,
                otherwise,
            } => {
                if let Some(o) = operand {
                    o.walk(f);
                }
                for (w, t) in whens {
                    w.walk(f);
                    t.walk(f);
                }
                if let Some(o) = otherwise {
                    o.walk(f);
                }
            }
            Self::Object(fields) => {
                for (_, e) in fields {
                    e.walk(f);
                }
            }
        }
    }

    /// Whether the expression reads the current row (any `Field`, `id()` or `rev()`).
    #[must_use]
    pub fn reads_row(&self) -> bool {
        let mut found = false;
        self.walk(&mut |e| {
            if matches!(e, Self::Field(_))
                || matches!(e, Self::Call { func, .. } if func.reads_row())
            {
                found = true;
            }
        });
        found
    }
}

/// Renders a static path in dot notation (backticks for names that need them), the form used
/// by index descriptors (data-model.md §2.2).
#[must_use]
pub fn path_text(steps: &[Step]) -> String {
    let mut out = String::new();
    for (i, s) in steps.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        match s {
            Step::Field {
                name,
                index: Some(_),
            } => out.push_str(name),
            Step::Field { name, index: None } => {
                let plain = !name.is_empty()
                    && !name.bytes().all(|b| b.is_ascii_digit())
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80);
                if plain {
                    out.push_str(name);
                } else {
                    out.push('`');
                    out.push_str(&name.replace('`', "``"));
                    out.push('`');
                }
            }
            Step::Dyn(_) => out.push_str("[?]"),
        }
    }
    out
}

pub use self::print::print_bexpr;
