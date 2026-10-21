//! Just enough of the GraphQL language to say what a request document asks its endpoint to do.
//!
//! A GraphQL endpoint serves reads and writes on one URL, so a capability that forwards an agent's
//! document is only as narrow as what the gateway checks that document for. [`read`] lexes an
//! executable document by the October 2021 specification and reports each operation's type and its
//! root selections; everything nested deeper is only bracket-matched, because nothing below the root
//! selection set can change what an operation does.
//!
//! It is strict on purpose. Anything it does not fully recognize is an error rather than a guess, so a
//! document the upstream might read differently from this reader is refused, never forwarded.
//!
//! The document is an agent's and is read before policy, so reading it holds nothing in proportion to it but the brackets open at once ([`read_bytes`]): tokens are lexed one at a time as the parser asks for them, names are slices of the document, and what is found is handed to a visitor rather than collected.

/// The type of one operation in a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    /// A read, written `query { ... }` or as the anonymous shorthand `{ ... }`.
    Query,
    /// A write.
    Mutation,
    /// A long-lived subscription.
    Subscription,
}

impl OperationType {
    /// The keyword that introduces this operation type.
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationType::Query => "query",
            OperationType::Mutation => "mutation",
            OperationType::Subscription => "subscription",
        }
    }
}

/// One selection in an operation's root selection set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSelection<'a> {
    /// A field, by its schema name: for `made: issueCreate(...)` this is `issueCreate`, not the alias.
    Field(&'a str),
    /// A fragment spread or inline fragment, whose fields this reader does not resolve.
    Fragment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token<'a> {
    Punct(u8),
    Spread,
    Name(&'a str),
    Str,
    Value,
}

/// Read every operation in `document`, handing `visit` each root selection in document order with the index and type of the operation it is in, and answer how many operations there are. Every operation has at least one root selection, so each is visited.
/// Fragment definitions are accepted and skipped; any other kind of definition, and any lexical or structural error, is an `Err` naming the problem. A lexical error anywhere in the document is the one named, so the answer is the same as if the whole document were lexed before it is parsed. On an `Err`, what was visited means nothing.
pub fn read<'a>(document: &'a str, mut visit: impl FnMut(usize, OperationType, RootSelection<'a>)) -> Result<usize, String> {
    let mut p = Parser { tokens: Tokens::new(document) };
    let parsed = p.operations(&mut visit);
    if parsed.is_err() {
        while p.tokens.lexer.next().is_some() {}
    }
    match p.tokens.lexer.error {
        Some(lexical) => Err(lexical.to_string()),
        None => parsed.map_err(str::to_string),
    }
}

/// The most [`read`] holds on the heap at once for `document`: the text of the error it may answer with, and the stack of brackets open inside one group, a byte each, in a `Vec` that holds its old buffer beside one twice as long while it grows, with the two chunk headers that takes. Every bracket character is counted, inside strings and comments too. [`aliases`] holds nothing.
pub fn read_bytes(document: &str) -> u64 {
    const ERROR_TEXT: u64 = 128;
    let open = document.bytes().filter(|b| matches!(b, b'(' | b'[' | b'{')).count() as u64;
    if open == 0 {
        return ERROR_TEXT;
    }
    // A `Vec<u8>`'s first buffer holds eight.
    ERROR_TEXT + 3 * open.max(8) + 32
}

/// Every `alias: field` pair in `document`, from anywhere in it: nested selections, fragments and inline fragments included, handed to `visit` in document order. A response key is the alias when there is one, so this is what maps a key the agent chose back to the field it names. Outside an argument list or a variable definition, where `name: value` is an argument or an input field, a name, a colon and a name is only ever an alias. A document this lexer cannot read is scanned for the same shape over its raw text, which can only find more pairs.
pub fn aliases<'a>(document: &'a str, mut visit: impl FnMut(&'a str, &'a str)) {
    if !lexes(document) {
        return raw_aliases(document, visit);
    }
    let mut tokens = Tokens::new(document);
    let mut depth = 0usize;
    while let Some(token) = tokens.next() {
        match token {
            Token::Punct(b'(') => depth += 1,
            Token::Punct(b')') => depth = depth.saturating_sub(1),
            Token::Name(alias) if depth == 0 => {
                if let (Some(Token::Punct(b':')), Some(Token::Name(field))) = (tokens.look(0), tokens.look(1)) {
                    visit(alias, field);
                }
            }
            _ => {}
        }
    }
}

/// Whether the whole of `document` lexes.
fn lexes(document: &str) -> bool {
    let mut lexer = Lexer::new(document);
    while lexer.next().is_some() {}
    lexer.error.is_none()
}

/// [`aliases`] over text the lexer refused: every name, colon, name sequence, with only GraphQL's ignored characters between them.
fn raw_aliases<'a>(document: &'a str, mut visit: impl FnMut(&'a str, &'a str)) {
    let b = document.as_bytes();
    // `None` is a colon; an empty name is any other character, which breaks a sequence. These are the two items before the one just read, and the document starts after two breaks.
    let mut before: [Option<&str>; 2] = [Some(""), Some("")];
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let item = if is_name_start(c) {
            let start = i;
            while i < b.len() && is_name_continue(b[i]) {
                i += 1;
            }
            Some(&document[start..i])
        } else {
            i += 1;
            match c {
                b':' => None,
                b' ' | b'\t' | b'\n' | b'\r' | b',' => continue,
                _ => Some(""),
            }
        };
        if let ([Some(alias), None], Some(field)) = (before, item) {
            if !alias.is_empty() && !field.is_empty() {
                visit(alias, field);
            }
        }
        before = [before[1], item];
    }
}

/// The tokens of a document as a parser reads them, with two of lookahead.
struct Tokens<'a> {
    lexer: Lexer<'a>,
    ahead: [Option<Token<'a>>; 2],
    held: usize,
}

impl<'a> Tokens<'a> {
    fn new(src: &'a str) -> Self {
        Tokens { lexer: Lexer::new(src), ahead: [None, None], held: 0 }
    }

    /// The token `n` (0 or 1) past the current one, without moving.
    fn look(&mut self, n: usize) -> Option<Token<'a>> {
        while self.held <= n {
            self.ahead[self.held] = self.lexer.next();
            self.held += 1;
        }
        self.ahead[n]
    }

    fn next(&mut self) -> Option<Token<'a>> {
        let token = self.look(0);
        self.ahead = [self.ahead[1], None];
        self.held -= 1;
        token
    }
}

struct Parser<'a> {
    tokens: Tokens<'a>,
}

impl<'a> Parser<'a> {
    fn peek(&mut self) -> Option<Token<'a>> {
        self.tokens.look(0)
    }

    fn next(&mut self) -> Option<Token<'a>> {
        self.tokens.next()
    }

    fn bump(&mut self) {
        self.tokens.next();
    }

    fn operations(&mut self, visit: &mut impl FnMut(usize, OperationType, RootSelection<'a>)) -> Result<usize, &'static str> {
        if self.peek().is_none() {
            return Err("the document is empty");
        }
        let mut count = 0;
        while let Some(mut token) = self.peek() {
            // Newer servers accept a description before an operation or fragment definition; refusing one would leave a document they run unread.
            if token == Token::Str {
                match self.tokens.look(1) {
                    Some(Token::Name(n)) if matches!(n, "query" | "mutation" | "subscription" | "fragment") => {
                        self.bump();
                        token = Token::Name(n);
                    }
                    _ => return Err("a description must come before an operation or fragment definition"),
                }
            }
            match token {
                Token::Punct(b'{') => {
                    self.root_selection_set(count, OperationType::Query, visit)?;
                    count += 1;
                }
                Token::Name(name) if matches!(name, "query" | "mutation" | "subscription") => {
                    let kind = match name {
                        "query" => OperationType::Query,
                        "mutation" => OperationType::Mutation,
                        _ => OperationType::Subscription,
                    };
                    self.bump();
                    if matches!(self.peek(), Some(Token::Name(_))) {
                        self.bump();
                    }
                    if self.peek() == Some(Token::Punct(b'(')) {
                        self.skip_group()?;
                    }
                    self.skip_directives()?;
                    self.root_selection_set(count, kind, visit)?;
                    count += 1;
                }
                Token::Name("fragment") => {
                    self.bump();
                    match self.next() {
                        Some(Token::Name(n)) if n != "on" => {}
                        _ => return Err("a fragment definition needs a name"),
                    }
                    if self.next() != Some(Token::Name("on")) {
                        return Err("a fragment definition needs a type condition");
                    }
                    if !matches!(self.next(), Some(Token::Name(_))) {
                        return Err("a fragment definition needs a type condition");
                    }
                    self.skip_directives()?;
                    if self.peek() != Some(Token::Punct(b'{')) {
                        return Err("a fragment definition needs a selection set");
                    }
                    self.skip_group()?;
                }
                _ => return Err("only operations and fragments may appear in a request document"),
            }
        }
        Ok(count)
    }

    /// Consume one bracketed group starting at the current `(`, `[` or `{`, through its matching close.
    fn skip_group(&mut self) -> Result<(), &'static str> {
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
                        return Err("the document's brackets do not match");
                    }
                    if stack.is_empty() {
                        return Ok(());
                    }
                }
                Some(_) if !stack.is_empty() => {}
                Some(_) => return Err("expected a bracketed group"),
                None => return Err("the document ends inside a bracketed group"),
            }
        }
    }

    fn skip_directives(&mut self) -> Result<(), &'static str> {
        while self.peek() == Some(Token::Punct(b'@')) {
            self.bump();
            if !matches!(self.next(), Some(Token::Name(_))) {
                return Err("a directive needs a name");
            }
            if self.peek() == Some(Token::Punct(b'(')) {
                self.skip_group()?;
            }
        }
        Ok(())
    }

    fn root_selection_set(
        &mut self,
        index: usize,
        kind: OperationType,
        visit: &mut impl FnMut(usize, OperationType, RootSelection<'a>),
    ) -> Result<(), &'static str> {
        if self.next() != Some(Token::Punct(b'{')) {
            return Err("an operation needs a selection set");
        }
        let mut any = false;
        loop {
            match self.next() {
                Some(Token::Punct(b'}')) if any => return Ok(()),
                Some(Token::Spread) => {
                    match self.peek() {
                        Some(Token::Name("on")) => {
                            self.bump();
                            if !matches!(self.next(), Some(Token::Name(_))) {
                                return Err("an inline fragment needs a type");
                            }
                            self.skip_directives()?;
                            self.skip_selection_set()?;
                        }
                        Some(Token::Name(_)) => {
                            self.bump();
                            self.skip_directives()?;
                        }
                        Some(Token::Punct(b'@' | b'{')) => {
                            self.skip_directives()?;
                            self.skip_selection_set()?;
                        }
                        _ => return Err("a spread needs a fragment name or an inline fragment"),
                    }
                    visit(index, kind, RootSelection::Fragment);
                    any = true;
                }
                Some(Token::Name(first)) => {
                    let name = if self.peek() == Some(Token::Punct(b':')) {
                        self.bump();
                        match self.next() {
                            Some(Token::Name(field)) => field,
                            _ => return Err("an alias must be followed by a field name"),
                        }
                    } else {
                        first
                    };
                    if self.peek() == Some(Token::Punct(b'(')) {
                        self.skip_group()?;
                    }
                    self.skip_directives()?;
                    if self.peek() == Some(Token::Punct(b'{')) {
                        self.skip_group()?;
                    }
                    visit(index, kind, RootSelection::Field(name));
                    any = true;
                }
                Some(_) => return Err("unexpected token in a selection set"),
                None => return Err("the document ends inside a selection set"),
            }
        }
    }

    fn skip_selection_set(&mut self) -> Result<(), &'static str> {
        if self.peek() != Some(Token::Punct(b'{')) {
            return Err("expected a selection set");
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

/// The tokens that carry structure, one at a time. A string is [`Token::Str`] and a number
/// [`Token::Value`]; whitespace, commas, comments and a byte order mark are ignored. The first error
/// ends the tokens and is kept in `error`.
///
/// Byte-wise is sound because every structural character is ASCII and no byte of a multi-byte UTF-8
/// sequence is below 0x80, so non-ASCII text can only appear inside a string or a comment, and is
/// refused anywhere else.
struct Lexer<'a> {
    src: &'a str,
    at: usize,
    error: Option<&'static str>,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Lexer { src, at: 0, error: None }
    }

    fn lex_one(&mut self) -> Result<Option<Token<'a>>, &'static str> {
        let src = self.src;
        let b = src.as_bytes();
        let mut i = self.at;
        let token = loop {
            let Some(&c) = b.get(i) else {
                self.at = i;
                return Ok(None);
            };
            match c {
                b' ' | b'\t' | b'\n' | b'\r' | b',' => i += 1,
                0xEF if b[i..].starts_with(&[0xEF, 0xBB, 0xBF]) => i += 3,
                b'#' => {
                    while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                        i += 1;
                    }
                }
                b'!' | b'$' | b'&' | b'(' | b')' | b':' | b'=' | b'@' | b'[' | b']' | b'{' | b'|' | b'}' => {
                    i += 1;
                    break Token::Punct(c);
                }
                b'.' => {
                    if !b[i..].starts_with(b"...") {
                        return Err("a lone '.' is not GraphQL");
                    }
                    i += 3;
                    break Token::Spread;
                }
                b'"' if b[i..].starts_with(b"\"\"\"") => {
                    i += 3;
                    loop {
                        if i >= b.len() {
                            return Err("unterminated block string");
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
                    break Token::Str;
                }
                b'"' => {
                    i += 1;
                    loop {
                        match b.get(i) {
                            None | Some(b'\n') | Some(b'\r') => return Err("unterminated string"),
                            Some(b'"') => {
                                i += 1;
                                break;
                            }
                            Some(b'\\') => match b.get(i + 1) {
                                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => i += 2,
                                Some(b'u') => i += 2 + unicode_escape_len(&b[i + 2..])?,
                                _ => return Err("invalid escape in a string"),
                            },
                            Some(_) => i += 1,
                        }
                    }
                    break Token::Str;
                }
                b'-' | b'0'..=b'9' => {
                    i = number_end(b, i)?;
                    break Token::Value;
                }
                c if is_name_start(c) => {
                    let start = i;
                    while i < b.len() && is_name_continue(b[i]) {
                        i += 1;
                    }
                    break Token::Name(&src[start..i]);
                }
                _ => return Err("the document contains a character GraphQL does not allow here"),
            }
        };
        self.at = i;
        Ok(Some(token))
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        match self.lex_one() {
            Ok(token) => token,
            Err(error) => {
                self.error = Some(error);
                self.at = self.src.len();
                None
            }
        }
    }
}

/// The length of a `\u` escape's payload: four hex digits, or `{hex}`.
fn unicode_escape_len(rest: &[u8]) -> Result<usize, &'static str> {
    if rest.first() == Some(&b'{') {
        let close = rest.iter().position(|&c| c == b'}').ok_or("invalid unicode escape")?;
        if !(2..=9).contains(&close) || !rest[1..close].iter().all(u8::is_ascii_hexdigit) {
            return Err("invalid unicode escape");
        }
        return Ok(close + 1);
    }
    if rest.len() >= 4 && rest[..4].iter().all(u8::is_ascii_hexdigit) {
        Ok(4)
    } else {
        Err("invalid unicode escape")
    }
}

/// The end of a numeric literal starting at `i`, by the specification's IntValue / FloatValue rules.
fn number_end(b: &[u8], mut i: usize) -> Result<usize, &'static str> {
    let digits = |b: &[u8], mut i: usize| -> Result<usize, &'static str> {
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err("invalid number");
        }
        Ok(i)
    };
    if b[i] == b'-' {
        i += 1;
    }
    if b.get(i) == Some(&b'0') {
        i += 1;
        if b.get(i).is_some_and(u8::is_ascii_digit) {
            return Err("invalid number");
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
        return Err("invalid number");
    }
    Ok(i)
}

#[cfg(test)]
mod before;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every operation as the reader before this one collected it: its type and its root selections.
    fn operations(doc: &str) -> Result<Vec<(OperationType, Vec<RootSelection<'_>>)>, String> {
        let mut ops: Vec<(OperationType, Vec<RootSelection>)> = Vec::new();
        let count = read(doc, |index, kind, selection| {
            if index == ops.len() {
                ops.push((kind, Vec::new()));
            }
            ops[index].1.push(selection);
        })?;
        assert_eq!(count, ops.len(), "every operation is visited");
        Ok(ops)
    }

    fn collected_aliases(doc: &str) -> Vec<(String, String)> {
        let mut found = Vec::new();
        aliases(doc, |alias, field| found.push((alias.to_string(), field.to_string())));
        found
    }

    fn kinds(doc: &str) -> Vec<OperationType> {
        operations(doc).unwrap().into_iter().map(|o| o.0).collect()
    }

    fn root(doc: &str) -> Vec<RootSelection<'_>> {
        let mut ops = operations(doc).unwrap();
        assert_eq!(ops.len(), 1, "{doc}");
        ops.remove(0).1
    }

    fn field(name: &str) -> RootSelection<'_> {
        RootSelection::Field(name)
    }

    #[test]
    fn reads_each_operation_type() {
        assert_eq!(kinds("{ viewer { id } }"), [OperationType::Query]);
        assert_eq!(kinds("query { viewer { id } }"), [OperationType::Query]);
        assert_eq!(kinds("query Q($a: Int = 1, $b: [String!]! = [\"x\"]) @d(x: {y: 1}) { viewer { id } }"), [OperationType::Query]);
        assert_eq!(kinds("mutation M { a }"), [OperationType::Mutation]);
        assert_eq!(kinds("subscription { a }"), [OperationType::Subscription]);
        assert_eq!(kinds("query A { a } mutation B { b }"), [OperationType::Query, OperationType::Mutation]);
        // An operation may be named after a keyword; it is still the type its own keyword says.
        assert_eq!(kinds("query mutation { a }"), [OperationType::Query]);
        assert_eq!(kinds("fragment F on Mutation { a } query { ...F }"), [OperationType::Query]);
        // A description names nothing; the keyword after it is still what decides.
        assert_eq!(kinds("\"Archive it\" mutation { a }"), [OperationType::Mutation]);
        assert_eq!(kinds("\"\"\"Read\"\"\" query { a } \"f\" fragment F on Q { a }"), [OperationType::Query]);
    }

    #[test]
    fn aliases_are_found_at_every_depth_and_in_fragments() {
        let doc = "query Q($first: Int = 5) { w: webhooks(first: $first, filter: { a: { eq: b } }) { nodes { id s: secret ...F ... on Webhook { t: token } } } } fragment F on Webhook { u: url @include(if: true) }";
        let found = collected_aliases(doc);
        assert_eq!(
            found,
            vec![
                ("w".to_string(), "webhooks".to_string()),
                ("s".to_string(), "secret".to_string()),
                ("t".to_string(), "token".to_string()),
                ("u".to_string(), "url".to_string()),
            ],
            "arguments, input objects, variable definitions and directive arguments are not aliases"
        );
    }

    #[test]
    fn an_unreadable_document_is_scanned_for_aliases_over_its_raw_text() {
        let found = collected_aliases("query { w: webhooks { nodes { s : secret } } } \u{1}");
        assert!(found.contains(&("w".to_string(), "webhooks".to_string())), "{found:?}");
        assert!(found.contains(&("s".to_string(), "secret".to_string())), "{found:?}");
    }

    #[test]
    fn root_fields_are_schema_names_not_aliases() {
        assert_eq!(root("mutation { made: issueCreate(input: {}) { success } }"), [field("issueCreate")]);
        assert_eq!(root("{ a @include(if: true) b(x: 1) { c } __typename }"), [field("a"), field("b"), field("__typename")]);
        assert_eq!(root("mutation { ...F ... on Mutation { b } ... @skip(if: false) { c } }").len(), 3);
        assert!(root("mutation { ...F }").iter().all(|s| *s == RootSelection::Fragment));
    }

    #[test]
    fn strings_comments_and_block_strings_hide_nothing_and_reveal_nothing() {
        assert_eq!(kinds("query { a(x: \"} mutation { b }\") }"), [OperationType::Query]);
        assert_eq!(kinds("# } mutation { b }\nquery { a }"), [OperationType::Query]);
        assert_eq!(kinds("query { a(x: \"\"\" \\\"\"\" } mutation { b } \"\"\") }"), [OperationType::Query]);
        assert_eq!(kinds("query { a(x: \"\\\"\") } mutation { b }"), [OperationType::Query, OperationType::Mutation]);
        // In a block string a backslash escapes only a triple quote, so `\\"""` still escapes it.
        assert_eq!(kinds("query { a(x: \"\"\"\\\\\"\"\" } mutation { b } \"\"\") }"), [OperationType::Query]);
        assert_eq!(kinds("query { a(x: \"\\u00e9\\u{1F600}\") }"), [OperationType::Query]);
        assert_eq!(kinds("\u{FEFF}query { a(x: \"caf\u{e9}\") } # caf\u{e9}"), [OperationType::Query]);
    }

    const REFUSED: &[&str] = &[
        "",
        "   # only a comment",
        "MUTATION { a }",
        "type Mutation { a: Int }",
        "extend type Query { a: Int }",
        "schema { query: Query }",
        "query { a ",
        "query { a } }",
        "query { a(x: [1}) }",
        "query { }",
        "query",
        "query { a(x: \"unterminated) }",
        "query { a(x: \"bad \\q escape\") }",
        "query { a(x: \"\\u12\") }",
        "query { a(x: \"\"\"unterminated) }",
        "query { a(x: \"line\nbreak\") }",
        "query { a(x: 01) }",
        "query { a(x: 1x) }",
        "query { a(x: 1.) }",
        "query { a(x: 1.5.2) }",
        "query { a(x: -) }",
        "query { a.b }",
        "query { a(x: 1) } ; mutation { b }",
        "query { caf\u{e9} }",
        "fragment on on Q { a }",
        "fragment F { a }",
        "query { ... }",
        "query { a: }",
        "query { \"value\" }",
        "\"description\" { a }",
        "\"description\"",
        "\"a\" \"b\" query { a }",
    ];

    #[test]
    fn anything_unrecognized_is_an_error() {
        for doc in REFUSED {
            assert!(read(doc, |_, _, _| {}).is_err(), "{doc:?} must be refused");
        }
    }

    const PIECES: [&str; 41] = [
        "{", "}", "(", ")", "[", "]", ":", "a", "b", "secret", "_x1", "query", "mutation", "subscription", "fragment", "on", "...",
        "\"s\"", "\"\"\"b\"\"\"", "\"\\u{1F600}\"", "\"open", "1", "-2.5e3", "01", "@", "$", "!", "=", "&", "|", "#c\n", " ", ",", "\n",
        "\u{1}", "\u{e9}", ".", "..", "__typename", "\u{FEFF}", "%",
    ];

    /// Documents built from GraphQL's executable grammar, deep and wide enough to reach every branch of the reader.
    struct Gen(u64);

    impl Gen {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }

        fn pick<'p>(&mut self, from: &[&'p str]) -> &'p str {
            from[self.below(from.len())]
        }

        fn name(&mut self, out: &mut String) {
            out.push_str(self.pick(&["a", "b", "secret", "on", "query", "mutation", "fragment", "_x1", "__typename", "viewer"]));
        }

        fn value(&mut self, out: &mut String, depth: usize) {
            match self.below(if depth > 2 { 4 } else { 6 }) {
                0 => out.push_str(self.pick(&["1", "-2.5e3", "0", "true", "null"])),
                1 => out.push_str(self.pick(&["\"s\"", "\"\"\"b \\\"\"\" }\"\"\"", "\"\\u00e9\""])),
                2 => out.push_str("$v"),
                3 => self.name(out),
                4 => {
                    out.push('[');
                    for _ in 0..self.below(3) {
                        self.value(out, depth + 1);
                        out.push(' ');
                    }
                    out.push(']');
                }
                _ => {
                    out.push('{');
                    for _ in 0..self.below(3) {
                        self.name(out);
                        out.push_str(": ");
                        self.value(out, depth + 1);
                        out.push(' ');
                    }
                    out.push('}');
                }
            }
        }

        fn arguments(&mut self, out: &mut String) {
            out.push('(');
            for _ in 0..=self.below(2) {
                self.name(out);
                out.push_str(": ");
                self.value(out, 0);
                out.push_str(", ");
            }
            out.push(')');
        }

        fn directives(&mut self, out: &mut String) {
            for _ in 0..self.below(2) {
                out.push_str(" @");
                self.name(out);
                if self.below(2) == 0 {
                    self.arguments(out);
                }
            }
        }

        fn selections(&mut self, out: &mut String, depth: usize) {
            out.push_str("{ ");
            for _ in 0..=self.below(3) {
                match self.below(if depth > 3 { 1 } else { 5 }) {
                    0..=2 => {
                        if self.below(2) == 0 {
                            self.name(out);
                            out.push_str(": ");
                        }
                        self.name(out);
                        if self.below(3) == 0 {
                            self.arguments(out);
                        }
                        self.directives(out);
                        if depth < 4 && self.below(2) == 0 {
                            out.push(' ');
                            self.selections(out, depth + 1);
                        }
                    }
                    3 => {
                        out.push_str("...");
                        self.name(out);
                        self.directives(out);
                    }
                    _ => {
                        out.push_str("... ");
                        if self.below(2) == 0 {
                            out.push_str("on ");
                            self.name(out);
                        }
                        self.directives(out);
                        out.push(' ');
                        self.selections(out, depth + 1);
                    }
                }
                out.push_str(self.pick(&[" ", ", ", "\n", " # c\n"]));
            }
            out.push('}');
        }

        fn document(&mut self, out: &mut String) {
            for _ in 0..=self.below(2) {
                if self.below(4) == 0 {
                    out.push_str(self.pick(&["\"d\" ", "\"\"\"d\"\"\" "]));
                }
                match self.below(4) {
                    0 => {}
                    1 => {
                        out.push_str("fragment ");
                        self.name(out);
                        out.push_str(" on ");
                        self.name(out);
                        self.directives(out);
                        out.push(' ');
                    }
                    _ => {
                        out.push_str(self.pick(&["query", "mutation", "subscription"]));
                        out.push(' ');
                        if self.below(2) == 0 {
                            self.name(out);
                        }
                        if self.below(3) == 0 {
                            out.push_str("($v: [Int!]! = [1], $w: String)");
                        }
                        self.directives(out);
                        out.push(' ');
                    }
                }
                self.selections(out, 0);
                out.push(' ');
            }
        }
    }

    /// The streaming reader against the one before it, which lexed the whole document into a vector first: the same answer, the same refusal text, and the same alias pairs in the same order, for every document here and many thousands generated from GraphQL's own pieces.
    #[test]
    fn reads_every_document_exactly_as_the_collecting_reader_did() {
        let (mut read_ok, mut with_aliases) = (0, 0);
        let mut compare = |doc: &str| {
            let old = before::operations(doc).map(|ops| {
                ops.into_iter()
                    .map(|op| {
                        let root = op.root.into_iter().map(|s| match s {
                            before::RootSelection::Field(name) => Some(name),
                            before::RootSelection::Fragment => None,
                        });
                        (op.kind, root.collect::<Vec<_>>())
                    })
                    .collect::<Vec<_>>()
            });
            let new = operations(doc).map(|ops| {
                ops.into_iter()
                    .map(|(kind, root)| {
                        let root = root.into_iter().map(|s| match s {
                            RootSelection::Field(name) => Some(name.to_string()),
                            RootSelection::Fragment => None,
                        });
                        (kind, root.collect::<Vec<_>>())
                    })
                    .collect::<Vec<_>>()
            });
            assert_eq!(new, old, "{doc:?}");
            read_ok += usize::from(new.is_ok());
            let found = collected_aliases(doc);
            with_aliases += usize::from(!found.is_empty());
            assert_eq!(found, before::aliases(doc), "{doc:?}");
        };

        for doc in REFUSED {
            compare(doc);
        }
        for doc in [
            "{ viewer { id } }",
            "query Q($a: Int = 1) @d(x: {y: 1}) { w: webhooks(f: $a) { nodes { s: secret } } } fragment F on W { u: url }",
            "\"d\" mutation { made: issueCreate(input: {}) { success } }",
            "{ a b c } { d }",
            "a:b:c:d",
            "{a:b a:b a:b}",
        ] {
            compare(doc);
        }
        let mut gen = Gen(0x9E37_79B9_7F4A_7C15);
        for _ in 0..30_000 {
            let mut doc = String::new();
            gen.document(&mut doc);
            compare(&doc);
            // The same document broken in one or two places: a piece dropped, a stray piece put in.
            for _ in 0..=gen.below(2) {
                let at = doc.char_indices().map(|(i, _)| i).nth(gen.below(doc.chars().count().max(1))).unwrap_or(0);
                if gen.below(2) == 0 && at < doc.len() {
                    let end = at + doc[at..].chars().next().map_or(0, char::len_utf8);
                    doc.replace_range(at..end, "");
                } else {
                    doc.insert_str(at, gen.pick(&PIECES));
                }
            }
            compare(&doc);
        }
        for _ in 0..30_000 {
            let len = gen.below(24);
            let doc: String = (0..len).map(|_| gen.pick(&PIECES)).collect();
            compare(&doc);
        }
        assert!(read_ok > 2_000 && with_aliases > 2_000, "the corpus exercises both: {read_ok} read, {with_aliases} with aliases");
    }
}
