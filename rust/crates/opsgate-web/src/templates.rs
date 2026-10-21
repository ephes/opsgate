//! The Jinja templates (PLAN.md 6.3): the template files of the Python
//! package (`src/opsgate/templates/*.html`), embedded at compile time and
//! rendered with minijinja and the globals and filters Flask gives them.
//!
//! - `url_for(endpoint, **args)` ([`crate::urls`]);
//! - `get_flashed_messages(with_categories=false, category_filter=())`,
//!   taking the request's flashes out of the session ([`SessionHandle`]);
//! - `csrf_token`: the session's token, created when the session has none
//!   (Flask's context processor runs `ensure_csrf_token` on every render);
//! - the filters `ui_datetime` and `tojson` (HTML-safe, sorted keys,
//!   optional `indent`).
//!
//! Templates ending in `.html` are autoescaped. Values print as Python's
//! `str()` prints them (`None`, `True`, float `repr`). The HTML bytes are P2;
//! the forms, fields, links and flashes are P1 (4.11).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use minijinja::value::{Kwargs, Object, ObjectRepr, Value as JinjaValue, ValueKind};
use minijinja::{AutoEscape, Environment, Error, ErrorKind, Output, State};
use opsgate_core::json::{PyNumber, py_float_repr, py_number};
use opsgate_core::pytext::strip;
use opsgate_core::time::parse_iso_datetime;
use serde_json::Value;

use crate::error::AppError;
use crate::session::SessionHandle;
use crate::urls::{UrlArg, url_for};

/// The template files of the Python package, by name.
pub const TEMPLATE_FILES: [(&str, &str); 5] = [
    (
        "forbidden.html",
        include_str!("../../../../src/opsgate/templates/forbidden.html"),
    ),
    (
        "login.html",
        include_str!("../../../../src/opsgate/templates/login.html"),
    ),
    (
        "ticket_detail.html",
        include_str!("../../../../src/opsgate/templates/ticket_detail.html"),
    ),
    (
        "ticket_log.html",
        include_str!("../../../../src/opsgate/templates/ticket_log.html"),
    ),
    (
        "tickets.html",
        include_str!("../../../../src/opsgate/templates/tickets.html"),
    ),
];

/// The template environment.
pub struct Templates {
    env: Environment<'static>,
}

impl std::fmt::Debug for Templates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Templates").finish_non_exhaustive()
    }
}

/// A rendering context: variable name → value.
pub type Context = BTreeMap<String, JinjaValue>;

impl Templates {
    /// The environment with every template compiled.
    pub fn new() -> Result<Self, Error> {
        let mut env = Environment::new();
        for (name, source) in TEMPLATE_FILES {
            env.add_template(name, source)?;
        }
        env.add_function("url_for", template_url_for);
        env.add_filter("ui_datetime", ui_datetime);
        env.add_filter("tojson", tojson);
        env.set_formatter(python_formatter);
        Ok(Self { env })
    }

    /// `render_template(name, **context)`: the page text. The session's CSRF
    /// token is created if needed; `context` wins over the globals, as with
    /// Flask's context processors.
    pub fn render(
        &self,
        name: &str,
        session: &SessionHandle,
        context: Context,
    ) -> Result<String, AppError> {
        let mut variables = Context::new();
        variables.insert(
            "csrf_token".to_owned(),
            JinjaValue::from(session.ensure_csrf_token()?),
        );
        let flashes = session.clone();
        variables.insert(
            "get_flashed_messages".to_owned(),
            JinjaValue::from_function(move |kwargs: Kwargs| {
                get_flashed_messages(&flashes, &kwargs)
            }),
        );
        variables.extend(context);
        self.env
            .get_template(name)
            .and_then(|template| template.render(JinjaValue::from(variables)))
            .map_err(|error| AppError::Internal(format!("template {name}: {error:#}")))
    }

    /// [`Templates::render`] as an HTML response with `status`.
    pub fn page(
        &self,
        name: &str,
        session: &SessionHandle,
        context: Context,
        status: StatusCode,
    ) -> Result<Response, AppError> {
        let html = self.render(name, session, context)?;
        Ok((
            status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            )],
            html,
        )
            .into_response())
    }
}

/// An integer beyond 128 bits (Python's integers are unbounded): printed
/// and written by `tojson` as its digits.
#[derive(Debug)]
struct BigInt(String);

impl Object for BigInt {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Plain
    }

    fn render(self: &Arc<Self>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A JSON value (a serialised ticket, a decoded request) as a template
/// value: objects keep their keys in sorted order, integers stay integers
/// (of any size), floats are `f64`.
pub fn to_template_value(value: &Value) -> JinjaValue {
    match value {
        Value::Null => JinjaValue::from(()),
        Value::Bool(flag) => JinjaValue::from(*flag),
        Value::Number(number) => match py_number(number) {
            PyNumber::Int(digits) => digits.parse::<i128>().map_or_else(
                |_| JinjaValue::from_object(BigInt(digits.into_owned())),
                JinjaValue::from,
            ),
            PyNumber::Float(float) => JinjaValue::from(float),
        },
        Value::String(text) => JinjaValue::from(text.as_str()),
        Value::Array(items) => {
            JinjaValue::from(items.iter().map(to_template_value).collect::<Vec<_>>())
        }
        Value::Object(map) => JinjaValue::from(
            map.iter()
                .map(|(key, item)| (key.clone(), to_template_value(item)))
                .collect::<BTreeMap<String, JinjaValue>>(),
        ),
    }
}

/// Prints values as Jinja2 does: Python's `str()` (`None`, `True`, a
/// float's `repr`) and, in HTML templates, MarkupSafe's escaping (`&`, `<`,
/// `>`, `'`, `"`; unlike minijinja's own escaping, `/` stays as it is).
fn python_formatter(out: &mut Output, state: &State, value: &JinjaValue) -> Result<(), Error> {
    let text = if value.is_number() && !value.is_integer() {
        match f64::try_from(value.clone()) {
            Ok(float) if float.is_finite() => py_float_repr(float),
            _ => value.to_string(),
        }
    } else {
        value.to_string()
    };
    let text = match state.auto_escape() {
        AutoEscape::Html if !value.is_safe() => markupsafe_escape(&text),
        AutoEscape::None | AutoEscape::Html => text,
        _ => return minijinja::escape_formatter(out, state, value),
    };
    out.write_str(&text)
        .map_err(|error| Error::new(ErrorKind::WriteFailure, error.to_string()))
}

/// `markupsafe.escape(text)`.
pub fn markupsafe_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\'' => escaped.push_str("&#39;"),
            '"' => escaped.push_str("&#34;"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn template_url_for(endpoint: String, kwargs: Kwargs) -> Result<String, Error> {
    let mut args = Vec::new();
    for key in kwargs.args() {
        let value: JinjaValue = kwargs.get(key)?;
        let arg = if value.is_none() || value.is_undefined() {
            UrlArg::None
        } else if let Some(number) = value.as_i64() {
            UrlArg::Int(number)
        } else {
            UrlArg::Text(value.to_string())
        };
        args.push((key, arg));
    }
    url_for(&endpoint, &args).map_err(|error| Error::new(ErrorKind::InvalidOperation, error.0))
}

fn get_flashed_messages(session: &SessionHandle, kwargs: &Kwargs) -> Result<JinjaValue, Error> {
    let with_categories: Option<bool> = kwargs.get("with_categories")?;
    let category_filter: Option<Vec<String>> = kwargs.get("category_filter")?;
    kwargs.assert_all_used()?;
    let mut flashes = session.flashed_messages();
    if let Some(filter) = category_filter.filter(|filter| !filter.is_empty()) {
        flashes.retain(|(category, _)| filter.contains(category));
    }
    Ok(JinjaValue::from(
        flashes
            .into_iter()
            .map(|(category, message)| {
                if with_categories.unwrap_or(false) {
                    JinjaValue::from(vec![JinjaValue::from(category), JinjaValue::from(message)])
                } else {
                    JinjaValue::from(message)
                }
            })
            .collect::<Vec<_>>(),
    ))
}

/// `ui_datetime`: `n/a` for a non-string or blank value, the stripped text
/// when it does not parse (4.9), else `%Y-%m-%d %H:%M UTC`.
fn ui_datetime(value: JinjaValue) -> String {
    let Some(raw) = value.as_str() else {
        return "n/a".to_owned();
    };
    let normalized = strip(raw);
    if normalized.is_empty() {
        return "n/a".to_owned();
    }
    match parse_iso_datetime(normalized) {
        Ok(parsed) => parsed.format("%Y-%m-%d %H:%M UTC").to_string(),
        Err(_) => normalized.to_owned(),
    }
}

/// Flask's `tojson` filter: JSON with sorted keys (indented when `indent`
/// is given, positionally or as `indent=…`), with `<`, `>`, `&` and `'` written as `\u` escapes so the
/// text is safe inside HTML; marked safe.
fn tojson(value: JinjaValue, indent: Option<usize>, kwargs: Kwargs) -> Result<JinjaValue, Error> {
    let indent = match kwargs.get::<Option<usize>>("indent")? {
        Some(width) => Some(width),
        None => indent,
    };
    kwargs.assert_all_used()?;
    let json = sorted(to_json(&value)?);
    let text = match indent {
        Some(width) => {
            let indent = " ".repeat(width);
            let mut out = Vec::new();
            let formatter = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
            let mut serializer = serde_json::Serializer::with_formatter(&mut out, formatter);
            serde::Serialize::serialize(&json, &mut serializer)
                .map_err(|error| Error::new(ErrorKind::BadSerialization, error.to_string()))?;
            String::from_utf8(out).unwrap_or_default()
        }
        None => serde_json::to_string(&json)
            .map_err(|error| Error::new(ErrorKind::BadSerialization, error.to_string()))?,
    };
    Ok(JinjaValue::from_safe_string(
        text.replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026")
            .replace('\'', "\\u0027"),
    ))
}

/// A template value as JSON, integers of any size included.
fn to_json(value: &JinjaValue) -> Result<Value, Error> {
    let bad = |error: serde_json::Error| Error::new(ErrorKind::BadSerialization, error.to_string());
    if let Some(big) = value.downcast_object_ref::<BigInt>() {
        // `arbitrary_precision` keeps every digit of the token.
        return serde_json::from_str(&big.0).map_err(bad);
    }
    match value.kind() {
        ValueKind::Map => {
            let mut map = serde_json::Map::new();
            for key in value.try_iter()? {
                let item = value.get_item(&key)?;
                let name = key.as_str().map_or_else(|| key.to_string(), str::to_owned);
                map.insert(name, to_json(&item)?);
            }
            Ok(Value::Object(map))
        }
        ValueKind::Seq | ValueKind::Iterable => Ok(Value::Array(
            value
                .try_iter()?
                .map(|item| to_json(&item))
                .collect::<Result<_, _>>()?,
        )),
        _ => serde_json::to_value(value).map_err(bad),
    }
}

/// The value with every object rebuilt in key order (independent of
/// `serde_json`'s map type).
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, item)| (key, sorted(item)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ui_datetime_follows_python() {
        for (input, expected) in [
            (
                JinjaValue::from("2026-10-21T08:09:10.123456Z"),
                "2026-10-21 08:09 UTC",
            ),
            (
                JinjaValue::from(" 2026-10-21T10:09:10+02:00 "),
                "2026-10-21 08:09 UTC",
            ),
            (JinjaValue::from("  "), "n/a"),
            (JinjaValue::from(" not a date "), "not a date"),
            (JinjaValue::from(()), "n/a"),
            (JinjaValue::from(5), "n/a"),
        ] {
            assert_eq!(ui_datetime(input.clone()), expected, "{input:?}");
        }
    }

    #[test]
    fn tojson_is_sorted_and_html_safe() {
        let value = to_template_value(&json!({"b": "<a href='x'>&</a>", "a": [1, 2.5]}));
        assert_eq!(
            tojson(
                value.clone(),
                None,
                Kwargs::from_iter(Vec::<(&str, JinjaValue)>::new())
            )
            .unwrap()
            .to_string(),
            r#"{"a":[1,2.5],"b":"\u003ca href=\u0027x\u0027\u003e\u0026\u003c/a\u003e"}"#
        );
        assert_eq!(
            tojson(
                to_template_value(&json!({"y": {}, "x": []})),
                None,
                Kwargs::from_iter([("indent", JinjaValue::from(2))])
            )
            .unwrap()
            .to_string(),
            "{\n  \"x\": [],\n  \"y\": {}\n}"
        );
    }

    #[test]
    fn integers_of_any_size() {
        let big = "1".repeat(40);
        let value = to_template_value(
            &serde_json::from_str(&format!(
                "{{\"big\": {big}, \"wide\": {}, \"x\": [-0, 1.5]}}",
                i128::MAX
            ))
            .unwrap(),
        );
        assert_eq!(
            tojson(
                value.clone(),
                None,
                Kwargs::from_iter(Vec::<(&str, JinjaValue)>::new())
            )
            .unwrap()
            .to_string(),
            format!("{{\"big\":{big},\"wide\":{},\"x\":[0,1.5]}}", i128::MAX)
        );
        let mut templates = Templates::new().unwrap();
        templates
            .env
            .add_template("big.html", "{{ v.big }}|{{ v.wide }}")
            .unwrap();
        let mut context = Context::new();
        context.insert("v".to_owned(), value);
        assert_eq!(
            templates
                .render("big.html", &SessionHandle::default(), context)
                .unwrap(),
            format!("{big}|{}", i128::MAX)
        );
    }

    #[test]
    fn values_print_as_jinja2_prints_them() {
        let mut templates = Templates::new().unwrap();
        templates
            .env
            .add_template(
                "values.html",
                "{{ a }}|{{ b }}|{{ c }}|{{ d }}|{{ e }}|{{ f }}|{{ g }}|{{ missing }}",
            )
            .unwrap();
        let mut context = Context::new();
        context.insert("a".to_owned(), to_template_value(&json!(null)));
        context.insert("b".to_owned(), to_template_value(&json!(true)));
        context.insert("c".to_owned(), to_template_value(&json!(1e16)));
        context.insert("d".to_owned(), JinjaValue::from("<a href='/x'>&\"</a>"));
        context.insert("e".to_owned(), to_template_value(&json!(3)));
        context.insert(
            "f".to_owned(),
            JinjaValue::from_safe_string("<b>".to_owned()),
        );
        context.insert("g".to_owned(), to_template_value(&json!(0.0001)));
        let rendered = templates
            .render("values.html", &SessionHandle::default(), context)
            .unwrap();
        assert_eq!(
            rendered,
            "None|True|1e+16|&lt;a href=&#39;/x&#39;&gt;&amp;&#34;&lt;/a&gt;|3|<b>|0.0001|"
        );
    }

    #[test]
    fn every_template_compiles() {
        let templates = Templates::new().unwrap();
        for (name, _) in TEMPLATE_FILES {
            assert!(templates.env.get_template(name).is_ok(), "{name}");
        }
    }
}
