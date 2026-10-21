//! The reader as it was before it streamed, kept verbatim as the oracle the streaming reader is compared against: every document either reads the same, or is refused by both.

#![allow(dead_code)]

use super::OperationType;

/// One selection in an operation's root selection set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RootSelection {
    /// A field, by its schema name: for `made: issueCreate(...)` this is `issueCreate`, not the alias.
    Field(String),
    /// A fragment spread or inline fragment, whose fields this reader does not resolve.
    Fragment,
}

/// One operation definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Operation {
    /// The operation type.
    pub kind: OperationType,
    /// Its root selections, in document order.
    pub root: Vec<RootSelection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Punct(u8),
    Spread,
    Name(String),
    Str,
    Value,
}

/// Read every operation in `document`. Fragment definitions are accepted and skipped; any other kind
/// of definition, and any lexical or structural error, is an `Err` naming the problem.
pub(super) fn operations(document: &str) -> Result<Vec<Operation>, String> {
    let tokens = lex(document)?;
    if tokens.is_empty() {
        return Err("the document is empty".into());
    }
    let mut p = Parser { tokens, pos: 0 };
    let mut ops = Vec::new();
    while let Some(mut token) = p.peek().cloned() {
        // Newer servers accept a description before an operation or fragment definition; refusing one would leave a document they run unread.
        if token == Token::Str {
            match p.tokens.get(p.pos + 1) {
                Some(Token::Name(n)) if matches!(n.as_str(), "query" | "mutation" | "subscription" | "fragment") => {
                    p.pos += 1;
                    token = Token::Name(n.clone());
                }
                _ => return Err("a description must come before an operation or fragment definition".into()),
            }
        }
        match token {
            Token::Punct(b'{') => ops.push(Operation { kind: OperationType::Query, root: p.root_selection_set()? }),
            Token::Name(name) if matches!(name.as_str(), "query" | "mutation" | "subscription") => {
                let kind = match name.as_str() {
                    "query" => OperationType::Query,
                    "mutation" => OperationType::Mutation,
                    _ => OperationType::Subscription,
                };
                p.pos += 1;
                if matches!(p.peek(), Some(Token::Name(_))) {
                    p.pos += 1;
                }
                if p.peek() == Some(&Token::Punct(b'(')) {
                    p.skip_group()?;
                }
                p.skip_directives()?;
                ops.push(Operation { kind, root: p.root_selection_set()? });
            }
            Token::Name(name) if name == "fragment" => {
                p.pos += 1;
                match p.next() {
                    Some(Token::Name(n)) if n != "on" => {}
                    _ => return Err("a fragment definition needs a name".into()),
                }
                if p.next() != Some(Token::Name("on".into())) {
                    return Err("a fragment definition needs a type condition".into());
                }
                if !matches!(p.next(), Some(Token::Name(_))) {
                    return Err("a fragment definition needs a type condition".into());
                }
                p.skip_directives()?;
                if p.peek() != Some(&Token::Punct(b'{')) {
                    return Err("a fragment definition needs a selection set".into());
                }
                p.skip_group()?;
            }
            _ => return Err("only operations and fragments may appear in a request document".into()),
        }
    }
    Ok(ops)
}

/// Every `alias: field` pair in `document`, from anywhere in it: nested selections, fragments and inline fragments included. A response key is the alias when there is one, so this is what maps a key the agent chose back to the field it names. Outside an argument list or a variable definition, where `name: value` is an argument or an input field, a name, a colon and a name is only ever an alias. A document this lexer cannot read is scanned for the same shape over its raw text, which can only find more pairs.
pub(super) fn aliases(document: &str) -> Vec<(String, String)> {
    let Ok(tokens) = lex(document) else { return raw_aliases(document) };
    let mut out = Vec::new();
    let mut depth = 0usize;
    for (i, token) in tokens.iter().enumerate() {
        match token {
            Token::Punct(b'(') => depth += 1,
            Token::Punct(b')') => depth = depth.saturating_sub(1),
            Token::Name(alias) if depth == 0 => {
                if let (Some(Token::Punct(b':')), Some(Token::Name(field))) = (tokens.get(i + 1), tokens.get(i + 2)) {
                    out.push((alias.clone(), field.clone()));
                }
            }
            _ => {}
        }
    }
    out
}

/// [`aliases`] over text the lexer refused: every name, colon, name sequence, with only GraphQL's ignored characters between them.
fn raw_aliases(document: &str) -> Vec<(String, String)> {
    let b = document.as_bytes();
    // `None` is a colon; an empty name is any other character, which breaks a sequence.
    let mut items: Vec<Option<&str>> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if is_name_start(c) {
            let start = i;
            while i < b.len() && is_name_continue(b[i]) {
                i += 1;
            }
            items.push(Some(&document[start..i]));
            continue;
        }
        match c {
            b':' => items.push(None),
            b' ' | b'\t' | b'\n' | b'\r' | b',' => {}
            _ => items.push(Some("")),
        }
        i += 1;
    }
    items
        .windows(3)
        .filter_map(|w| match w {
            [Some(alias), None, Some(field)] if !alias.is_empty() && !field.is_empty() => {
                Some((alias.to_string(), field.to_string()))
            }
            _ => None,
        })
        .collect()
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        token
    }

    /// Consume one bracketed group starting at the current `(`, `[` or `{`, through its matching close.
    fn skip_group(&mut self) -> Result<(), String> {
        let mut stack: Vec<u8> = Vec::new();
        loop {
            match self.next() {
                Some(Token::Punct(open @ (b'(' | b'[' | b'{'))) => stack.push(match open {
                    b'(' => b')',
                    b'[' => b']',
                    _ => b'}',
                }),
                Some(Token::Punct(close @ (b')' | b']' | b'}'))) => {
                    if stack.pop() != Some(close) {
                        return Err("the document's brackets do not match".into());
                    }
                    if stack.is_empty() {
                        return Ok(());
                    }
                }
                Some(_) if !stack.is_empty() => {}
                Some(_) => return Err("expected a bracketed group".into()),
                None => return Err("the document ends inside a bracketed group".into()),
            }
        }
    }

    fn skip_directives(&mut self) -> Result<(), String> {
        while self.peek() == Some(&Token::Punct(b'@')) {
            self.pos += 1;
            if !matches!(self.next(), Some(Token::Name(_))) {
                return Err("a directive needs a name".into());
            }
            if self.peek() == Some(&Token::Punct(b'(')) {
                self.skip_group()?;
            }
        }
        Ok(())
    }

    fn root_selection_set(&mut self) -> Result<Vec<RootSelection>, String> {
        if self.next() != Some(Token::Punct(b'{')) {
            return Err("an operation needs a selection set".into());
        }
        let mut root = Vec::new();
        loop {
            match self.next() {
                Some(Token::Punct(b'}')) if !root.is_empty() => return Ok(root),
                Some(Token::Spread) => {
                    match self.peek().cloned() {
                        Some(Token::Name(n)) if n == "on" => {
                            self.pos += 1;
                            if !matches!(self.next(), Some(Token::Name(_))) {
                                return Err("an inline fragment needs a type".into());
                            }
                            self.skip_directives()?;
                            self.skip_selection_set()?;
                        }
                        Some(Token::Name(_)) => {
                            self.pos += 1;
                            self.skip_directives()?;
                        }
                        Some(Token::Punct(b'@' | b'{')) => {
                            self.skip_directives()?;
                            self.skip_selection_set()?;
                        }
                        _ => return Err("a spread needs a fragment name or an inline fragment".into()),
                    }
                    root.push(RootSelection::Fragment);
                }
                Some(Token::Name(first)) => {
                    let name = if self.peek() == Some(&Token::Punct(b':')) {
                        self.pos += 1;
                        match self.next() {
                            Some(Token::Name(field)) => field,
                            _ => return Err("an alias must be followed by a field name".into()),
                        }
                    } else {
                        first
                    };
                    if self.peek() == Some(&Token::Punct(b'(')) {
                        self.skip_group()?;
                    }
                    self.skip_directives()?;
                    if self.peek() == Some(&Token::Punct(b'{')) {
                        self.skip_group()?;
                    }
                    root.push(RootSelection::Field(name));
                }
                Some(_) => return Err("unexpected token in a selection set".into()),
                None => return Err("the document ends inside a selection set".into()),
            }
        }
    }

    fn skip_selection_set(&mut self) -> Result<(), String> {
        if self.peek() != Some(&Token::Punct(b'{')) {
            return Err("expected a selection set".into());
        }
        self.skip_group()
    }
}

fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_name_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Lex `src` into the tokens that carry structure. A string is [`Token::Str`] and a number
/// [`Token::Value`]; whitespace, commas, comments and a byte order mark are ignored.
///
/// Byte-wise is sound because every structural character is ASCII and no byte of a multi-byte UTF-8
/// sequence is below 0x80, so non-ASCII text can only appear inside a string or a comment, and is
/// refused anywhere else.
fn lex(src: &str) -> Result<Vec<Token>, String> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' | b',' => i += 1,
            0xEF if b[i..].starts_with(&[0xEF, 0xBB, 0xBF]) => i += 3,
            b'#' => {
                while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                    i += 1;
                }
            }
            b'!' | b'$' | b'&' | b'(' | b')' | b':' | b'=' | b'@' | b'[' | b']' | b'{' | b'|' | b'}' => {
                out.push(Token::Punct(c));
                i += 1;
            }
            b'.' => {
                if !b[i..].starts_with(b"...") {
                    return Err("a lone '.' is not GraphQL".into());
                }
                out.push(Token::Spread);
                i += 3;
            }
            b'"' if b[i..].starts_with(b"\"\"\"") => {
                i += 3;
                loop {
                    if i >= b.len() {
                        return Err("unterminated block string".into());
                    }
                    if b[i..].starts_with(b"\\\"\"\"") {
                        i += 4;
                    } else if b[i..].starts_with(b"\"\"\"") {
                        i += 3;
                        break;
                    } else {
                        i += 1;
                    }
                }
                out.push(Token::Str);
            }
            b'"' => {
                i += 1;
                loop {
                    match b.get(i) {
                        None | Some(b'\n') | Some(b'\r') => return Err("unterminated string".into()),
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        Some(b'\\') => match b.get(i + 1) {
                            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => i += 2,
                            Some(b'u') => i += 2 + unicode_escape_len(&b[i + 2..])?,
                            _ => return Err("invalid escape in a string".into()),
                        },
                        Some(_) => i += 1,
                    }
                }
                out.push(Token::Str);
            }
            b'-' | b'0'..=b'9' => {
                i = number_end(b, i)?;
                out.push(Token::Value);
            }
            c if is_name_start(c) => {
                let start = i;
                while i < b.len() && is_name_continue(b[i]) {
                    i += 1;
                }
                out.push(Token::Name(src[start..i].to_string()));
            }
            _ => return Err("the document contains a character GraphQL does not allow here".into()),
        }
    }
    Ok(out)
}

/// The length of a `\u` escape's payload: four hex digits, or `{hex}`.
fn unicode_escape_len(rest: &[u8]) -> Result<usize, String> {
    if rest.first() == Some(&b'{') {
        let close = rest.iter().position(|&c| c == b'}').ok_or("invalid unicode escape")?;
        if !(2..=9).contains(&close) || !rest[1..close].iter().all(u8::is_ascii_hexdigit) {
            return Err("invalid unicode escape".into());
        }
        return Ok(close + 1);
    }
    if rest.len() >= 4 && rest[..4].iter().all(u8::is_ascii_hexdigit) {
        Ok(4)
    } else {
        Err("invalid unicode escape".into())
    }
}

/// The end of a numeric literal starting at `i`, by the specification's IntValue / FloatValue rules.
fn number_end(b: &[u8], mut i: usize) -> Result<usize, String> {
    let digits = |b: &[u8], mut i: usize| -> Result<usize, String> {
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err("invalid number".into());
        }
        Ok(i)
    };
    if b[i] == b'-' {
        i += 1;
    }
    if b.get(i) == Some(&b'0') {
        i += 1;
        if b.get(i).is_some_and(u8::is_ascii_digit) {
            return Err("invalid number".into());
        }
    } else {
        i = digits(b, i)?;
    }
    if b.get(i) == Some(&b'.') {
        i = digits(b, i + 1)?;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        i = digits(b, i)?;
    }
    if b.get(i).is_some_and(|&c| c == b'.' || is_name_start(c)) {
        return Err("invalid number".into());
    }
    Ok(i)
}
