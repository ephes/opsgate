//! The P1 elements of a page (PLAN.md 4.11, 6.3) read with an HTML
//! tokenizer, never by bytes: forms with their action, method and fields
//! (inputs, selects with their options, textareas), links, flash messages
//! and the page's text. Contents of `<template>` elements (the step editor's
//! blueprint) are kept apart from the page's forms, as browsers do.

use html5gum::{DefaultEmitter, Token, Tokenizer};

/// One form field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// `input:<type>`, `select` or `textarea`.
    pub kind: String,
    pub name: String,
    /// An input's `value`, a textarea's text, a select's selected option.
    pub value: String,
    /// A select's options: `(value, label, selected)`.
    pub options: Vec<(String, String, bool)>,
}

/// One form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub id: String,
    pub fields: Vec<Field>,
}

impl Form {
    /// The first field named `name`.
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.name == name)
    }

    /// The value of the first field named `name`.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.field(name).map(|field| field.value.as_str())
    }

    /// The field names, in order.
    pub fn names(&self) -> Vec<&str> {
        self.fields
            .iter()
            .map(|field| field.name.as_str())
            .collect()
    }
}

/// A parsed page.
#[derive(Debug, Clone, Default)]
pub struct Page {
    pub title: String,
    pub forms: Vec<Form>,
    /// `href` of every link outside `<template>`.
    pub links: Vec<String>,
    /// `(category, message)` of every `<p class="flash-…">`.
    pub flashes: Vec<(String, String)>,
    /// The text outside `<script>`, `<style>` and `<template>`, entities
    /// decoded.
    pub text: String,
    /// Elements by `id`: `(id, attributes)` (to check `hidden`).
    pub ids: Vec<(String, Vec<(String, String)>)>,
}

impl Page {
    /// The form posting to `action`.
    pub fn form(&self, action: &str) -> Option<&Form> {
        self.forms.iter().find(|form| form.action == action)
    }

    /// Whether the page has a form posting to `action`.
    pub fn has_form(&self, action: &str) -> bool {
        self.form(action).is_some()
    }

    /// The attributes of the element with `id`.
    pub fn element(&self, id: &str) -> Option<&[(String, String)]> {
        self.ids
            .iter()
            .find(|(element, _)| element == id)
            .map(|(_, attributes)| attributes.as_slice())
    }
}

/// An open `<select>`: its name and its options so far.
type OpenSelect = Option<(String, Vec<(String, String, bool)>)>;
/// An open `<option>`: its `value` attribute, label and `selected` flag.
type OpenOption = Option<(Option<String>, String, bool)>;

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Parses `html`.
pub fn parse(html: &str) -> Page {
    let mut emitter = DefaultEmitter::default();
    emitter.naively_switch_states(true);
    let mut page = Page::default();
    let mut form: Option<Form> = None;
    // The open select: (name, options).
    let mut select: OpenSelect = None;
    // The open option: (value attribute, label, selected).
    let mut option: OpenOption = None;
    let mut textarea: Option<(String, String)> = None;
    let mut flash: Option<(String, String)> = None;
    let mut title: Option<String> = None;
    let mut raw_depth = 0_usize; // inside <script>/<style>
    let mut template_depth = 0_usize;

    let close_option = |select: &mut OpenSelect, option: &mut OpenOption| {
        if let (Some((_, options)), Some((value, label, selected))) =
            (select.as_mut(), option.take())
        {
            let label = label.trim().to_owned();
            options.push((value.unwrap_or_else(|| label.clone()), label, selected));
        }
    };

    for token in Tokenizer::new_with_emitter(html, emitter) {
        let Ok(token) = token;
        match token {
            Token::StartTag(tag) => {
                let name = text(&tag.name);
                let attributes: Vec<(String, String)> = tag
                    .attributes
                    .iter()
                    .map(|(key, value)| (text(key), text(&value.value)))
                    .collect();
                let attribute = |key: &str| {
                    attributes
                        .iter()
                        .find(|(name, _)| name == key)
                        .map(|(_, value)| value.clone())
                };
                if let Some(id) = attribute("id") {
                    page.ids.push((id, attributes.clone()));
                }
                match name.as_str() {
                    "script" | "style" => raw_depth += 1,
                    "template" => template_depth += 1,
                    "title" => title = Some(String::new()),
                    _ => {}
                }
                if template_depth > 0 {
                    continue;
                }
                match name.as_str() {
                    "form" => {
                        form = Some(Form {
                            action: attribute("action").unwrap_or_default(),
                            method: attribute("method").unwrap_or_default().to_lowercase(),
                            id: attribute("id").unwrap_or_default(),
                            fields: Vec::new(),
                        });
                    }
                    "input" => {
                        if let (Some(form), Some(field)) = (form.as_mut(), attribute("name")) {
                            form.fields.push(Field {
                                kind: format!("input:{}", attribute("type").unwrap_or_default()),
                                name: field,
                                value: attribute("value").unwrap_or_default(),
                                options: Vec::new(),
                            });
                        }
                    }
                    "select" => select = Some((attribute("name").unwrap_or_default(), Vec::new())),
                    "option" => {
                        close_option(&mut select, &mut option);
                        option = Some((
                            attribute("value"),
                            String::new(),
                            attribute("selected").is_some(),
                        ));
                    }
                    "textarea" => {
                        textarea = Some((attribute("name").unwrap_or_default(), String::new()))
                    }
                    "a" => {
                        if let Some(href) = attribute("href") {
                            page.links.push(href);
                        }
                    }
                    "p" => {
                        if let Some(category) = attribute("class")
                            .and_then(|class| class.strip_prefix("flash-").map(str::to_owned))
                        {
                            flash = Some((category, String::new()));
                        }
                    }
                    _ => {}
                }
            }
            Token::EndTag(tag) => {
                let name = text(&tag.name);
                match name.as_str() {
                    "script" | "style" => raw_depth = raw_depth.saturating_sub(1),
                    "template" => template_depth = template_depth.saturating_sub(1),
                    "title" => {
                        if let Some(title) = title.take() {
                            page.title = title;
                        }
                    }
                    _ => {}
                }
                if template_depth > 0 {
                    continue;
                }
                match name.as_str() {
                    "form" => page.forms.extend(form.take()),
                    "option" => close_option(&mut select, &mut option),
                    "select" => {
                        close_option(&mut select, &mut option);
                        if let (Some(form), Some((name, options))) = (form.as_mut(), select.take())
                            && !name.is_empty()
                        {
                            let value = options
                                .iter()
                                .find(|(_, _, selected)| *selected)
                                .or(options.first())
                                .map(|(value, _, _)| value.clone())
                                .unwrap_or_default();
                            form.fields.push(Field {
                                kind: "select".to_owned(),
                                name,
                                value,
                                options,
                            });
                        }
                    }
                    "textarea" => {
                        if let (Some(form), Some((name, content))) =
                            (form.as_mut(), textarea.take())
                            && !name.is_empty()
                        {
                            // The HTML parser drops one newline after `<textarea>`.
                            let value = content.strip_prefix('\n').unwrap_or(&content).to_owned();
                            form.fields.push(Field {
                                kind: "textarea".to_owned(),
                                name,
                                value,
                                options: Vec::new(),
                            });
                        }
                    }
                    "p" => page.flashes.extend(flash.take()),
                    _ => {}
                }
            }
            Token::String(string) => {
                let chunk = text(&string.value);
                if let Some(title) = title.as_mut() {
                    title.push_str(&chunk);
                }
                if raw_depth > 0 || template_depth > 0 {
                    continue;
                }
                if let Some((_, label, _)) = option.as_mut() {
                    label.push_str(&chunk);
                }
                if let Some((_, content)) = textarea.as_mut() {
                    content.push_str(&chunk);
                }
                if let Some((_, message)) = flash.as_mut() {
                    message.push_str(&chunk);
                }
                page.text.push_str(&chunk);
            }
            _ => {}
        }
    }
    page
}
