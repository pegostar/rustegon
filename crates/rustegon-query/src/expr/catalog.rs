// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The scalar function catalog of M3 (query-language.md §4.2) and the names reserved for later
//! milestones.
//!
//! Every normative name of §4.2 is known here: a scalar function evaluable per row is a [`Func`]
//! with an arity range checked at bind time (`RGN-1011`); aggregate, window, search and
//! document/system functions that need M7/M8 machinery are recognised and rejected as
//! unsupported (not as unknown); any other name is `RGN-1012 UnknownFunction`.

/// A scalar function (query-language.md §4.2).
#[allow(missing_docs)] // One variant per normative function name, documented in the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Func {
    // Type.
    TypeOf,
    IsNumber,
    IsString,
    ToString,
    ToInt,
    ToFloat,
    ToDecimal,
    ToDate,
    ToBool,
    ToOid,
    Coalesce,
    IfNull,
    // Arithmetic.
    Abs,
    Ceil,
    Floor,
    Round,
    Trunc,
    Sqrt,
    Pow,
    Exp,
    Ln,
    Log10,
    Mod,
    Greatest,
    Least,
    // String.
    Length,
    Lower,
    Upper,
    Trim,
    Ltrim,
    Rtrim,
    Substr,
    IndexOf,
    Replace,
    Split,
    Concat,
    StartsWith,
    EndsWith,
    RegexMatch,
    RegexExtract,
    Format,
    // Date.
    Now,
    DateTrunc,
    DateAdd,
    DateDiff,
    DateFormat,
    TimeBucket,
    /// `extract(unit FROM d)` (dedicated AST node).
    Extract,
    // Array.
    Size,
    ArrayContains,
    Slice,
    ArrayConcat,
    ArrayDistinct,
    ArraySort,
    ArrayReverse,
    Filter,
    Map,
    Reduce,
    First,
    Last,
    Zip,
    Range,
    ArrayToObject,
    ObjectToArray,
    // Object.
    Keys,
    Values,
    MergeObjects,
    GetField,
    SetField,
    UnsetField,
    // Conditional.
    If,
    Switch,
    // Document.
    Id,
    Rev,
}

/// Classification of a function name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuncClass {
    /// A scalar function of M3 with its arity range (`max = usize::MAX`: variadic).
    Scalar(Func, usize, usize),
    /// A known name whose evaluation belongs to a later milestone (feature, milestone).
    Deferred(&'static str, &'static str),
}

/// Scalar functions: name, function, minimum and maximum arity.
const SCALARS: &[(&str, Func, usize, usize)] = &[
    ("type_of", Func::TypeOf, 1, 1),
    ("is_number", Func::IsNumber, 1, 1),
    ("is_string", Func::IsString, 1, 1),
    ("to_string", Func::ToString, 1, 1),
    ("to_int", Func::ToInt, 1, 1),
    ("to_float", Func::ToFloat, 1, 1),
    ("to_decimal", Func::ToDecimal, 1, 1),
    ("to_date", Func::ToDate, 1, 1),
    ("to_bool", Func::ToBool, 1, 1),
    ("to_oid", Func::ToOid, 1, 1),
    ("coalesce", Func::Coalesce, 1, usize::MAX),
    ("if_null", Func::IfNull, 2, 2),
    ("abs", Func::Abs, 1, 1),
    ("ceil", Func::Ceil, 1, 1),
    ("floor", Func::Floor, 1, 1),
    ("round", Func::Round, 1, 2),
    ("trunc", Func::Trunc, 1, 1),
    ("sqrt", Func::Sqrt, 1, 1),
    ("pow", Func::Pow, 2, 2),
    ("exp", Func::Exp, 1, 1),
    ("ln", Func::Ln, 1, 1),
    ("log10", Func::Log10, 1, 1),
    ("mod", Func::Mod, 2, 2),
    ("greatest", Func::Greatest, 1, usize::MAX),
    ("least", Func::Least, 1, usize::MAX),
    ("length", Func::Length, 1, 1),
    ("lower", Func::Lower, 1, 1),
    ("upper", Func::Upper, 1, 1),
    ("trim", Func::Trim, 1, 1),
    ("ltrim", Func::Ltrim, 1, 1),
    ("rtrim", Func::Rtrim, 1, 1),
    ("substr", Func::Substr, 2, 3),
    ("index_of", Func::IndexOf, 2, 2),
    ("replace", Func::Replace, 3, 3),
    ("split", Func::Split, 2, 2),
    ("concat", Func::Concat, 1, usize::MAX),
    ("starts_with", Func::StartsWith, 2, 2),
    ("ends_with", Func::EndsWith, 2, 2),
    ("regex_match", Func::RegexMatch, 2, 2),
    ("regex_extract", Func::RegexExtract, 2, 3),
    ("format", Func::Format, 1, usize::MAX),
    ("now", Func::Now, 0, 0),
    ("date_trunc", Func::DateTrunc, 2, 2),
    ("date_add", Func::DateAdd, 3, 3),
    ("date_diff", Func::DateDiff, 3, 3),
    ("date_format", Func::DateFormat, 2, 3),
    ("time_bucket", Func::TimeBucket, 2, 3),
    ("size", Func::Size, 1, 1),
    ("array_contains", Func::ArrayContains, 2, 2),
    ("slice", Func::Slice, 2, 3),
    ("array_concat", Func::ArrayConcat, 1, usize::MAX),
    ("array_distinct", Func::ArrayDistinct, 1, 1),
    ("array_sort", Func::ArraySort, 1, 1),
    ("array_reverse", Func::ArrayReverse, 1, 1),
    ("filter", Func::Filter, 2, 2),
    ("map", Func::Map, 2, 2),
    ("reduce", Func::Reduce, 3, 3),
    ("first", Func::First, 1, 1),
    ("last", Func::Last, 1, 1),
    ("zip", Func::Zip, 1, usize::MAX),
    ("range", Func::Range, 2, 3),
    ("array_to_object", Func::ArrayToObject, 1, 1),
    ("object_to_array", Func::ObjectToArray, 1, 1),
    ("keys", Func::Keys, 1, 1),
    ("values", Func::Values, 1, 1),
    ("merge_objects", Func::MergeObjects, 1, usize::MAX),
    ("get_field", Func::GetField, 2, 2),
    ("set_field", Func::SetField, 3, 3),
    ("unset_field", Func::UnsetField, 2, 2),
    ("if", Func::If, 3, 3),
    ("switch", Func::Switch, 3, usize::MAX),
    ("id", Func::Id, 0, 0),
    ("rev", Func::Rev, 0, 0),
];

/// Names recognised but executed by later milestones (§4.2): feature and milestone.
const DEFERRED: &[(&str, &str, &str)] = &[
    ("count", "aggregate functions", "M7"),
    ("count_distinct", "aggregate functions", "M7"),
    ("count_distinct_approx", "aggregate functions", "M7"),
    ("sum", "aggregate functions", "M7"),
    ("avg", "aggregate functions", "M7"),
    ("min", "aggregate functions", "M7"),
    ("max", "aggregate functions", "M7"),
    ("array_agg", "aggregate functions", "M7"),
    ("set_agg", "aggregate functions", "M7"),
    ("percentile", "aggregate functions", "M7"),
    ("stddev_pop", "aggregate functions", "M7"),
    ("stddev_samp", "aggregate functions", "M7"),
    ("var_pop", "aggregate functions", "M7"),
    ("var_samp", "aggregate functions", "M7"),
    ("top_k", "aggregate functions", "M7"),
    ("row_number", "window functions", "M7"),
    ("rank", "window functions", "M7"),
    ("dense_rank", "window functions", "M7"),
    ("lag", "window functions", "M7"),
    ("lead", "window functions", "M7"),
    ("moving_avg", "window functions", "M7"),
    ("rate", "window functions", "M7"),
    ("cumulative_sum", "window functions", "M7"),
    ("derivative", "window functions", "M7"),
    ("interpolate", "window functions", "M7"),
    ("gap_fill", "window functions", "M7"),
    ("search", "full-text search", "M7"),
    ("score", "full-text search", "M7"),
    ("highlight", "full-text search", "M7"),
    ("vector_near", "vector search", "M9"),
    ("vector_distance", "vector search", "M9"),
    ("vector_rank", "vector search", "M9"),
    ("rrf", "hybrid search", "M9"),
    ("geo_within", "geospatial queries", "M7"),
    ("geo_intersects", "geospatial queries", "M7"),
    ("geo_near", "geospatial queries", "M7"),
    ("geo_distance", "geospatial queries", "M7"),
    ("geo_circle", "geospatial queries", "M7"),
    ("geo_box", "geospatial queries", "M7"),
    ("load", "document dereference load()", "M7"),
    ("counter", "counters", "M8"),
    ("writetime", "wide-column tables", "M8"),
    ("ttl", "wide-column tables", "M8"),
    ("metadata", "document metadata()", "M8"),
];

/// Classifies a function name (case-insensitive, query-language.md §4.2); `None` = unknown
/// (`RGN-1012`).
#[must_use]
pub fn lookup_function(name: &str) -> Option<FuncClass> {
    let lower = name.to_ascii_lowercase();
    if let Some(&(_, f, min, max)) = SCALARS.iter().find(|(n, ..)| *n == lower) {
        return Some(FuncClass::Scalar(f, min, max));
    }
    DEFERRED
        .iter()
        .find(|(n, ..)| *n == lower)
        .map(|&(_, feature, milestone)| FuncClass::Deferred(feature, milestone))
}

impl Func {
    /// The normative name.
    #[must_use]
    pub fn name(self) -> &'static str {
        if self == Self::Extract {
            return "extract";
        }
        SCALARS
            .iter()
            .find(|(_, f, ..)| *f == self)
            .map_or("?", |(n, ..)| n)
    }

    /// Whether the function reads the current row itself (not through its arguments).
    #[must_use]
    pub fn reads_row(self) -> bool {
        matches!(self, Self::Id | Self::Rev)
    }

    /// Whether the result may differ between two calls with equal arguments in one statement
    /// (constant folding must leave such calls alone). `now()` is the transaction timestamp,
    /// fixed per statement but unknown at bind time.
    #[must_use]
    pub fn is_volatile(self) -> bool {
        matches!(self, Self::Now | Self::Id | Self::Rev)
    }

    /// Indexes of arguments that must be lambdas, with their parameter count.
    #[must_use]
    pub fn lambda_args(self) -> &'static [(usize, usize)] {
        match self {
            Self::Filter | Self::Map => &[(1, 1)],
            Self::Reduce => &[(2, 2)],
            _ => &[],
        }
    }
}
