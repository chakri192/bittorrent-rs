//! Just enough JSON for `--json`: a writer for flat objects, one per line,
//! and a strict reader for the same, so that what is written can be checked
//! (in tests, and by the end-to-end harness) by something other than the
//! writer itself.
//!
//! Flat means the values are strings, numbers, booleans and `null`: no
//! nesting. That is all the status events need, and it keeps both halves
//! small enough to be obviously right.

use std::collections::BTreeMap;

/// A flat JSON object under construction. Keys keep the order they are
/// added in.
#[derive(Debug, Default)]
pub struct Object {
    buf: String,
}

impl Object {
    pub fn new() -> Self {
        Object { buf: String::new() }
    }

    fn key(&mut self, key: &str) {
        if !self.buf.is_empty() {
            self.buf.push(',');
        }
        self.buf.push('"');
        escape_into(key, &mut self.buf);
        self.buf.push_str("\":");
    }

    pub fn string(mut self, key: &str, value: &str) -> Self {
        self.key(key);
        self.buf.push('"');
        escape_into(value, &mut self.buf);
        self.buf.push('"');
        self
    }

    /// `None` is written as `null`.
    pub fn opt_string(self, key: &str, value: Option<&str>) -> Self {
        match value {
            Some(v) => self.string(key, v),
            None => self.null(key),
        }
    }

    pub fn uint(mut self, key: &str, value: u64) -> Self {
        self.key(key);
        self.buf.push_str(&value.to_string());
        self
    }

    /// `None` is written as `null`.
    pub fn opt_uint(self, key: &str, value: Option<u64>) -> Self {
        match value {
            Some(v) => self.uint(key, v),
            None => self.null(key),
        }
    }

    /// A number with the given digits after the point. JSON has no NaN or
    /// infinity, so those are written as `null`.
    pub fn float(mut self, key: &str, value: f64, decimals: usize) -> Self {
        if !value.is_finite() {
            return self.null(key);
        }
        self.key(key);
        self.buf.push_str(&format!("{:.*}", decimals, value));
        self
    }

    pub fn boolean(mut self, key: &str, value: bool) -> Self {
        self.key(key);
        self.buf.push_str(if value { "true" } else { "false" });
        self
    }

    pub fn null(mut self, key: &str) -> Self {
        self.key(key);
        self.buf.push_str("null");
        self
    }

    /// The finished object, `{...}`, with no trailing newline.
    pub fn finish(self) -> String {
        format!("{{{}}}", self.buf)
    }
}

/// `s` as the inside of a JSON string.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    escape_into(s, &mut out);
    out
}

fn escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

/// A value in a flat object.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Number(f64),
    Bool(bool),
    Null,
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Reads one flat JSON object. Strict: it refuses trailing commas, a
/// duplicate key, unescaped control characters in strings, bad escapes,
/// numbers JSON does not allow (`01`, `+1`, `.5`), nesting, and anything
/// after the closing brace.
pub fn parse_object(text: &str) -> Result<BTreeMap<String, Value>, String> {
    let mut p = Parser { chars: text.chars().collect(), pos: 0 };
    p.skip_ws();
    p.expect('{')?;
    let mut map = BTreeMap::new();
    p.skip_ws();
    if p.peek() == Some('}') {
        p.pos += 1;
    } else {
        loop {
            p.skip_ws();
            let key = p.string()?;
            p.skip_ws();
            p.expect(':')?;
            p.skip_ws();
            let value = p.value()?;
            if map.insert(key.clone(), value).is_some() {
                return Err(format!("duplicate key {:?}", key));
            }
            p.skip_ws();
            match p.next() {
                Some(',') => continue,
                Some('}') => break,
                other => return Err(format!("expected ',' or '}}', found {:?}", other)),
            }
        }
    }
    p.skip_ws();
    if p.pos != p.chars.len() {
        return Err("unexpected text after the object".to_string());
    }
    Ok(map)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek();
        self.pos += 1;
        c
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, want: char) -> Result<(), String> {
        match self.next() {
            Some(c) if c == want => Ok(()),
            other => Err(format!("expected {:?}, found {:?}", want, other)),
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), String> {
        for want in word.chars() {
            self.expect(want)?;
        }
        Ok(())
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some('"') => self.string().map(Value::String),
            Some('t') => self.literal("true").map(|_| Value::Bool(true)),
            Some('f') => self.literal("false").map(|_| Value::Bool(false)),
            Some('n') => self.literal("null").map(|_| Value::Null),
            Some('-' | '0'..='9') => self.number(),
            Some('{' | '[') => Err("nesting is not supported".to_string()),
            other => Err(format!("unexpected {:?} where a value should be", other)),
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        match self.peek() {
            Some('0') => {
                self.pos += 1;
                if matches!(self.peek(), Some('0'..='9')) {
                    return Err("a number cannot have a leading zero".to_string());
                }
            }
            Some('1'..='9') => self.digits(),
            _ => return Err("a number needs a digit".to_string()),
        }
        if self.peek() == Some('.') {
            self.pos += 1;
            if !matches!(self.peek(), Some('0'..='9')) {
                return Err("a fraction needs a digit".to_string());
            }
            self.digits();
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some('0'..='9')) {
                return Err("an exponent needs a digit".to_string());
            }
            self.digits();
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        text.parse::<f64>().map(Value::Number).map_err(|_| format!("not a number: {}", text))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some('0'..='9')) {
            self.pos += 1;
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            match self.next() {
                None => return Err("unterminated string".to_string()),
                Some('"') => return Ok(out),
                Some('\\') => match self.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('b') => out.push('\u{08}'),
                    Some('f') => out.push('\u{0c}'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('u') => out.push(self.unicode_escape()?),
                    other => return Err(format!("bad escape \\{:?}", other)),
                },
                Some(c) if (c as u32) < 0x20 => return Err("an unescaped control character in a string".to_string()),
                Some(c) => out.push(c),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let mut n = 0u32;
        for _ in 0..4 {
            let digit = self.next().and_then(|c| c.to_digit(16)).ok_or("a \\u escape needs four hex digits")?;
            n = n * 16 + digit;
        }
        Ok(n)
    }

    /// After `\u`: one code unit, or a surrogate pair written as two.
    fn unicode_escape(&mut self) -> Result<char, String> {
        let first = self.hex4()?;
        let code = match first {
            0xD800..=0xDBFF => {
                self.expect('\\').and_then(|_| self.expect('u')).map_err(|_| "a high surrogate must be followed by a low one".to_string())?;
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err("a high surrogate must be followed by a low one".to_string());
                }
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err("a lone low surrogate".to_string()),
            other => other,
        };
        char::from_u32(code).ok_or_else(|| "not a character".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_is_written_in_the_order_its_fields_were_added() {
        let line = Object::new().string("event", "progress").uint("done", 5).boolean("endgame", false).finish();
        assert_eq!(line, r#"{"event":"progress","done":5,"endgame":false}"#);
        assert_eq!(Object::new().finish(), "{}");
    }

    #[test]
    fn optional_and_non_finite_numbers_become_null() {
        let line = Object::new().opt_uint("eta", None).opt_uint("left", Some(7)).float("rate", f64::NAN, 1).float("inf", f64::INFINITY, 1).float("ok", 2.5, 1).null("n").finish();
        assert_eq!(line, r#"{"eta":null,"left":7,"rate":null,"inf":null,"ok":2.5,"n":null}"#);
    }

    #[test]
    fn strings_are_escaped_as_json_requires() {
        assert_eq!(escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape("line\nbreak\ttab\r"), r"line\nbreak\ttab\r");
        assert_eq!(escape("\u{08}\u{0c}"), r"\b\f");
        assert_eq!(escape("\u{01}\u{1f}"), r"\u0001\u001f");
        assert_eq!(escape("plain, non-ASCII: naïve 日本語 🎬"), "plain, non-ASCII: naïve 日本語 🎬", "printable text is left as it is");
        assert_eq!(escape("\u{7f}"), "\u{7f}", "DEL is not a JSON control character");
    }

    #[test]
    fn keys_are_escaped_too() {
        let line = Object::new().uint("we\"ird\nkey", 1).finish();
        assert_eq!(parse_object(&line).unwrap()["we\"ird\nkey"], Value::Number(1.0));
    }

    #[test]
    fn whatever_is_written_reads_back_the_same() {
        let nasty = "quote \" backslash \\ newline \n tab \t nul \u{0} bell \u{7} esc \u{1b} unit-sep \u{1f} emoji 🎬 CJK 日本語 slash / end";
        let line = Object::new().string("s", nasty).uint("n", u64::MAX).float("f", 12.375, 3).boolean("t", true).boolean("f2", false).null("z").finish();

        let read = parse_object(&line).unwrap();

        assert_eq!(read["s"], Value::String(nasty.to_string()));
        assert_eq!(read["n"].as_f64(), Some(u64::MAX as f64));
        assert_eq!(read["f"], Value::Number(12.375));
        assert_eq!((read["t"].as_bool(), read["f2"].as_bool()), (Some(true), Some(false)));
        assert_eq!(read["z"], Value::Null);
        assert!(!line.contains('\n'), "one object is one line");
    }

    #[test]
    fn the_reader_accepts_what_json_allows() {
        let read = parse_object(" { \"a\" : -0 , \"b\":1.5e+3,\"c\":\"\\u00e9\\ud83c\\udfac\\/\" ,\"d\":0.0 } ").unwrap();
        assert_eq!(read["a"], Value::Number(0.0));
        assert_eq!(read["b"], Value::Number(1500.0));
        assert_eq!(read["c"], Value::String("é🎬/".to_string()), "\\u escapes, a surrogate pair and an escaped slash");
        assert!(parse_object("{}").unwrap().is_empty());
        assert!(parse_object("\n{\"x\":1}\n").is_ok(), "whitespace around it is fine");
    }

    #[test]
    fn the_reader_refuses_what_json_does_not_allow() {
        for bad in [
            "", "{", "}", "{\"a\":1,}", "{,\"a\":1}", "{\"a\":1 \"b\":2}", "{\"a\"}", "{\"a\":}", "{a:1}", "{'a':1}",
            "{\"a\":01}", "{\"a\":+1}", "{\"a\":.5}", "{\"a\":1.}", "{\"a\":1e}", "{\"a\":-}", "{\"a\":NaN}", "{\"a\":Infinity}",
            "{\"a\":\"line\nbreak\"}", "{\"a\":\"tab\there\"}", "{\"a\":\"\\x41\"}", "{\"a\":\"\\u12\"}", "{\"a\":\"\\ud800\"}", "{\"a\":\"\\udc00\"}", "{\"a\":\"open}",
            "{\"a\":1,\"a\":2}", "{\"a\":[1]}", "{\"a\":{}}", "{\"a\":1} x", "{\"a\":1}{\"b\":2}", "{\"a\":tru}", "{\"a\":nul}",
        ] {
            assert!(parse_object(bad).is_err(), "{:?} should be refused", bad);
        }
    }

    #[test]
    fn numbers_survive_a_round_trip_at_the_precision_written() {
        for value in [0.0, 0.1, 99.9, 1234567.891, 1e-7, 1e15] {
            let line = Object::new().float("v", value, 6).finish();
            let read = parse_object(&line).unwrap()["v"].as_f64().unwrap();
            assert!((read - value).abs() < 1e-6, "{} came back as {}", value, read);
        }
    }
}
