// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! RGQL lexer (query-language.md §2).
//!
//! The whole input is tokenized before parsing, so a lexical error is always reported at its own
//! position regardless of what the parser would have done earlier. Positions are 1-based lines
//! and 1-based columns counted in Unicode scalar values (a tab counts as one column).
//!
//! Keywords are not distinguished here: every bare word is a [`TokenKind::Word`] and the parser
//! decides from context (keywords are case-insensitive, identifiers case-sensitive).

use super::error::ParseError;

/// Token kinds.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    /// Bare word: keyword or identifier `[A-Za-z_][A-Za-z0-9_]*`.
    Word(String),
    /// Backtick-quoted identifier (never a keyword).
    QuotedIdent(String),
    /// String literal (escapes resolved).
    Str(String),
    /// Number literal; the text excludes a sign and the decimal suffix.
    Number {
        /// Digits, optional fraction and exponent.
        text: String,
        /// Lexical class.
        class: NumberClass,
    },
    /// `$name` or `$1` (the text after `$`).
    Param(String),
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `,`
    Comma,
    /// `;`
    Semicolon,
    /// `:`
    Colon,
    /// `.`
    Dot,
    /// `*`
    Star,
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `/`
    Slash,
    /// `%`
    Percent,
    /// `=`
    Eq,
    /// `==`
    EqEq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `||` or `‖`
    Concat,
    /// `|>`
    Pipe,
    /// `->`
    Arrow,
    /// End of input.
    Eof,
}

/// Lexical class of a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberClass {
    /// Digits only.
    Int,
    /// Has a fraction or an exponent.
    Float,
    /// Has the `m` suffix.
    Decimal,
}

/// A token with its source position.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    /// Kind and payload.
    pub kind: TokenKind,
    /// Byte offset of the first character.
    pub start: usize,
    /// Byte offset after the last character.
    pub end: usize,
    /// 1-based line.
    pub line: u32,
    /// 1-based column (Unicode scalar values).
    pub column: u32,
}

/// Tokenizes `src`. The result always ends with an [`TokenKind::Eof`] token.
///
/// # Errors
/// [`ParseError::Syntax`] at the offending character: unknown character, unterminated string,
/// quoted identifier or block comment, invalid escape, malformed number or parameter.
pub fn tokenize(src: &str) -> Result<Vec<Token>, ParseError> {
    let mut lx = Lexer {
        src,
        pos: 0,
        line: 1,
        column: 1,
        tokens: Vec::new(),
    };
    lx.run()?;
    Ok(lx.tokens)
}

struct Lexer<'s> {
    src: &'s str,
    pos: usize,
    line: u32,
    column: u32,
    tokens: Vec<Token>,
}

/// Saved position for error reporting at a token start.
#[derive(Clone, Copy)]
struct Mark {
    pos: usize,
    line: u32,
    column: u32,
}

impl Lexer<'_> {
    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn peek2(&self) -> Option<char> {
        let mut it = self.src[self.pos..].chars();
        it.next();
        it.next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(c)
    }

    fn mark(&self) -> Mark {
        Mark {
            pos: self.pos,
            line: self.line,
            column: self.column,
        }
    }

    fn error(&self, at: Mark, message: &str) -> ParseError {
        let found = self.src[at.pos..].chars().next().map_or_else(
            || "end of input".to_owned(),
            |c| format!("{:?}", c.to_string()),
        );
        ParseError::syntax(at.line, at.column, found, vec![], Some(message.to_owned()))
    }

    fn push(&mut self, at: Mark, kind: TokenKind) {
        self.tokens.push(Token {
            kind,
            start: at.pos,
            end: self.pos,
            line: at.line,
            column: at.column,
        });
    }

    fn run(&mut self) -> Result<(), ParseError> {
        loop {
            self.skip_trivia()?;
            let at = self.mark();
            let Some(c) = self.peek() else {
                self.push(at, TokenKind::Eof);
                return Ok(());
            };
            let kind = match c {
                'A'..='Z' | 'a'..='z' | '_' => TokenKind::Word(self.word()),
                '0'..='9' => self.number(at)?,
                '\'' => TokenKind::Str(self.string(at)?),
                '`' => TokenKind::QuotedIdent(self.quoted_ident(at)?),
                '$' => self.param(at)?,
                _ => self.punct(at, c)?,
            };
            self.push(at, kind);
        }
    }

    fn skip_trivia(&mut self) -> Result<(), ParseError> {
        loop {
            match (self.peek(), self.peek2()) {
                (Some(c), _) if c.is_whitespace() => {
                    self.bump();
                }
                (Some('-'), Some('-')) => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                (Some('/'), Some('*')) => {
                    let at = self.mark();
                    self.bump();
                    self.bump();
                    loop {
                        match (self.peek(), self.peek2()) {
                            (Some('*'), Some('/')) => {
                                self.bump();
                                self.bump();
                                break;
                            }
                            (Some(_), _) => {
                                self.bump();
                            }
                            (None, _) => return Err(self.error(at, "unterminated block comment")),
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn word(&mut self) -> String {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            self.bump();
        }
        self.src[start..self.pos].to_owned()
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.bump();
        }
        self.pos - start
    }

    /// Numbers: `digits [. digits] [(e|E) [+|-] digits] [m]`. Directly after a `.` token only
    /// plain digits are read, so `a.0.1` is the path `a`, `0`, `1` and not `a` followed by `0.1`.
    fn number(&mut self, at: Mark) -> Result<TokenKind, ParseError> {
        let after_dot = matches!(self.tokens.last(), Some(t) if t.kind == TokenKind::Dot);
        let start = self.pos;
        self.digits();
        let mut class = NumberClass::Int;
        if !after_dot {
            if self.peek() == Some('.') && self.peek2().is_some_and(|c| c.is_ascii_digit()) {
                self.bump();
                self.digits();
                class = NumberClass::Float;
            }
            if matches!(self.peek(), Some('e' | 'E')) {
                self.bump();
                if matches!(self.peek(), Some('+' | '-')) {
                    self.bump();
                }
                if self.digits() == 0 {
                    return Err(self.error(at, "malformed number: exponent has no digits"));
                }
                class = NumberClass::Float;
            }
        }
        let text = self.src[start..self.pos].to_owned();
        if !after_dot && self.peek() == Some('m') {
            self.bump();
            class = NumberClass::Decimal;
        }
        if self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(self.error(at, "malformed number: letters directly after the digits"));
        }
        Ok(TokenKind::Number { text, class })
    }

    fn string(&mut self, at: Mark) -> Result<String, ParseError> {
        self.bump();
        let mut out = String::new();
        loop {
            let esc = self.mark();
            match self.bump() {
                None => return Err(self.error(at, "unterminated string literal")),
                Some('\'') if self.peek() == Some('\'') => {
                    self.bump();
                    out.push('\'');
                }
                Some('\'') => return Ok(out),
                Some('\\') => out.push(self.escape(esc)?),
                Some(c) => out.push(c),
            }
        }
    }

    /// Backslash escapes `\n \t \\ \' \u{…}` (§2); anything else is rejected so that a future
    /// escape cannot silently change the meaning of existing text.
    fn escape(&mut self, at: Mark) -> Result<char, ParseError> {
        match self.bump() {
            Some('n') => Ok('\n'),
            Some('t') => Ok('\t'),
            Some('\\') => Ok('\\'),
            Some('\'') => Ok('\''),
            Some('u') if self.peek() == Some('{') => {
                self.bump();
                let start = self.pos;
                while self.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                    self.bump();
                }
                let hex = &self.src[start..self.pos];
                let ok = (1..=6).contains(&hex.len()) && self.peek() == Some('}');
                let c = u32::from_str_radix(hex, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .filter(|_| ok);
                match c {
                    Some(c) => {
                        self.bump();
                        Ok(c)
                    }
                    None => Err(self.error(at, "invalid \\u{…} escape")),
                }
            }
            _ => Err(self.error(at, "invalid escape (allowed: \\n \\t \\\\ \\' \\u{…})")),
        }
    }

    fn quoted_ident(&mut self, at: Mark) -> Result<String, ParseError> {
        self.bump();
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(self.error(at, "unterminated quoted identifier")),
                Some('`') if self.peek() == Some('`') => {
                    self.bump();
                    out.push('`');
                }
                Some('`') if out.is_empty() => {
                    return Err(self.error(at, "empty quoted identifier"));
                }
                Some('`') => return Ok(out),
                Some(c) => out.push(c),
            }
        }
    }

    /// `$name` (`[A-Za-z_][A-Za-z0-9_]*`) or `$n` (1-based, no leading zero, so that the
    /// printed form of a position is unique).
    fn param(&mut self, at: Mark) -> Result<TokenKind, ParseError> {
        self.bump();
        match self.peek() {
            Some('A'..='Z' | 'a'..='z' | '_') => Ok(TokenKind::Param(self.word())),
            Some('1'..='9') => {
                let start = self.pos;
                self.digits();
                let text = self.src[start..self.pos].to_owned();
                if text.parse::<u32>().is_err() {
                    return Err(self.error(at, "parameter position out of range"));
                }
                if self
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    return Err(self.error(at, "malformed parameter"));
                }
                Ok(TokenKind::Param(text))
            }
            _ => Err(self.error(at, "expected a parameter name or position after `$`")),
        }
    }

    fn punct(&mut self, at: Mark, c: char) -> Result<TokenKind, ParseError> {
        let next = self.peek2();
        let (kind, len) = match (c, next) {
            ('=', Some('=')) => (TokenKind::EqEq, 2),
            ('!', Some('=')) => (TokenKind::Ne, 2),
            ('<', Some('=')) => (TokenKind::Le, 2),
            ('>', Some('=')) => (TokenKind::Ge, 2),
            ('|', Some('|')) => (TokenKind::Concat, 2),
            ('|', Some('>')) => (TokenKind::Pipe, 2),
            ('-', Some('>')) => (TokenKind::Arrow, 2),
            ('(', _) => (TokenKind::LParen, 1),
            (')', _) => (TokenKind::RParen, 1),
            ('[', _) => (TokenKind::LBracket, 1),
            (']', _) => (TokenKind::RBracket, 1),
            ('{', _) => (TokenKind::LBrace, 1),
            ('}', _) => (TokenKind::RBrace, 1),
            (',', _) => (TokenKind::Comma, 1),
            (';', _) => (TokenKind::Semicolon, 1),
            (':', _) => (TokenKind::Colon, 1),
            ('.', _) => (TokenKind::Dot, 1),
            ('*', _) => (TokenKind::Star, 1),
            ('+', _) => (TokenKind::Plus, 1),
            ('-', _) => (TokenKind::Minus, 1),
            ('/', _) => (TokenKind::Slash, 1),
            ('%', _) => (TokenKind::Percent, 1),
            ('=', _) => (TokenKind::Eq, 1),
            ('<', _) => (TokenKind::Lt, 1),
            ('>', _) => (TokenKind::Gt, 1),
            ('\u{2016}', _) => (TokenKind::Concat, 1),
            _ => return Err(self.error(at, "unexpected character")),
        };
        for _ in 0..len {
            self.bump();
        }
        Ok(kind)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        tokenize(src).unwrap().into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn lexer_path_digits_after_dot_are_integers() {
        let k = kinds("a.0.1");
        assert_eq!(k.len(), 6);
        assert!(
            matches!(&k[2], TokenKind::Number { text, class: NumberClass::Int } if text == "0")
        );
    }

    #[test]
    fn lexer_string_escapes_resolve() {
        assert_eq!(
            kinds(r"'it''s\n\u{e9}\\'")[0],
            TokenKind::Str("it's\né\\".into())
        );
    }

    #[test]
    fn lexer_columns_count_scalar_values() {
        let t = tokenize("'é' x").unwrap();
        assert_eq!((t[1].line, t[1].column), (1, 5));
        let t = tokenize("a\n  b").unwrap();
        assert_eq!((t[1].line, t[1].column), (2, 3));
    }

    #[test]
    fn lexer_comments_are_skipped() {
        assert_eq!(kinds("a -- x\n/* y */ b").len(), 3);
    }
}
