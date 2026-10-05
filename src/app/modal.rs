//! Modal dialogs: confirmation, PIN entry, forms, text viewers.

use zeroize::Zeroizing;

use super::App;

pub type OnConfirm = Box<dyn FnOnce(&mut App)>;
pub type OnPin = Box<dyn FnOnce(&mut App, Zeroizing<String>)>;
pub type OnSubmit = Box<dyn Fn(&mut App, &[Field]) -> Result<(), String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Success,
    Warn,
    Error,
}

pub enum Modal {
    Help {
        scroll: u16,
    },
    Message {
        title: String,
        body: Vec<String>,
        level: Level,
    },
    Text {
        title: String,
        lines: Vec<String>,
        scroll: u16,
    },
    Confirm(Confirm),
    Pin(PinPrompt),
    Form(Form),
}

pub struct Confirm {
    pub title: String,
    pub body: Vec<String>,
    pub danger: bool,
    /// When set, the user must type this word to enable the confirm button.
    pub type_to_confirm: Option<String>,
    pub typed: String,
    pub yes_selected: bool,
    pub yes_label: String,
    pub on_yes: Option<OnConfirm>,
}

impl Confirm {
    pub fn new(title: impl Into<String>, body: Vec<String>, on_yes: OnConfirm) -> Self {
        Self {
            title: title.into(),
            body,
            danger: false,
            type_to_confirm: None,
            typed: String::new(),
            yes_selected: false,
            yes_label: "Confirm".into(),
            on_yes: Some(on_yes),
        }
    }

    pub fn danger(mut self, word: Option<&str>) -> Self {
        self.danger = true;
        self.type_to_confirm = word.map(String::from);
        self
    }

    pub fn yes_label(mut self, l: &str) -> Self {
        self.yes_label = l.into();
        self
    }

    pub fn can_confirm(&self) -> bool {
        self.type_to_confirm
            .as_ref()
            .is_none_or(|w| self.typed.trim() == w)
    }
}

pub struct PinPrompt {
    pub title: String,
    pub reason: String,
    pub input: Zeroizing<String>,
    pub reveal: bool,
    pub retries: Option<u32>,
    pub min_len: usize,
    pub error: Option<String>,
    pub on_submit: Option<OnPin>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Secret,
    Number { min: i64, max: i64 },
    Toggle,
    Choice(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub label: String,
    pub kind: FieldKind,
    pub value: String,
    pub checked: bool,
    pub choice: usize,
    pub hint: Option<String>,
}

impl Field {
    pub fn text(label: &str, value: &str) -> Self {
        Self {
            label: label.into(),
            kind: FieldKind::Text,
            value: value.into(),
            checked: false,
            choice: 0,
            hint: None,
        }
    }

    pub fn secret(label: &str) -> Self {
        Self {
            kind: FieldKind::Secret,
            ..Self::text(label, "")
        }
    }

    pub fn number(label: &str, value: i64, min: i64, max: i64) -> Self {
        Self {
            kind: FieldKind::Number { min, max },
            ..Self::text(label, &value.to_string())
        }
    }

    pub fn toggle(label: &str, checked: bool) -> Self {
        Self {
            kind: FieldKind::Toggle,
            checked,
            ..Self::text(label, "")
        }
    }

    pub fn choice(label: &str, options: &[&str], selected: usize) -> Self {
        Self {
            kind: FieldKind::Choice(options.iter().map(|s| s.to_string()).collect()),
            choice: selected,
            ..Self::text(label, "")
        }
    }

    pub fn hint(mut self, h: &str) -> Self {
        self.hint = Some(h.into());
        self
    }

    pub fn is_text_like(&self) -> bool {
        matches!(
            self.kind,
            FieldKind::Text | FieldKind::Secret | FieldKind::Number { .. }
        )
    }

    pub fn choice_label(&self) -> &str {
        match &self.kind {
            FieldKind::Choice(o) => o.get(self.choice).map(String::as_str).unwrap_or(""),
            _ => "",
        }
    }

    pub fn number_value(&self) -> Result<i64, String> {
        let FieldKind::Number { min, max } = self.kind else {
            return Err("not a number field".into());
        };
        let n: i64 = self
            .value
            .trim()
            .parse()
            .map_err(|_| format!("{} must be a number", self.label))?;
        if n < min || n > max {
            return Err(format!("{} must be between {min} and {max}", self.label));
        }
        Ok(n)
    }

    pub fn input_char(&mut self, c: char) {
        match self.kind {
            FieldKind::Number { .. } if !c.is_ascii_digit() => {}
            FieldKind::Text | FieldKind::Secret | FieldKind::Number { .. } => self.value.push(c),
            FieldKind::Toggle if c == ' ' => self.checked = !self.checked,
            _ => {}
        }
    }

    pub fn cycle(&mut self, forward: bool) {
        match &self.kind {
            FieldKind::Choice(o) if !o.is_empty() => {
                self.choice = if forward {
                    (self.choice + 1) % o.len()
                } else {
                    (self.choice + o.len() - 1) % o.len()
                };
            }
            FieldKind::Toggle => self.checked = !self.checked,
            _ => {}
        }
    }
}

impl Drop for Form {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for f in self
            .fields
            .iter_mut()
            .filter(|f| f.kind == FieldKind::Secret)
        {
            f.value.zeroize();
        }
    }
}

pub struct Form {
    pub title: String,
    pub description: Vec<String>,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub error: Option<String>,
    pub submit_label: String,
    pub on_submit: OnSubmit,
}

impl Form {
    pub fn new(title: impl Into<String>, fields: Vec<Field>, on_submit: OnSubmit) -> Self {
        Self {
            title: title.into(),
            description: Vec::new(),
            fields,
            focus: 0,
            error: None,
            submit_label: "Save".into(),
            on_submit,
        }
    }

    pub fn describe(mut self, lines: &[&str]) -> Self {
        self.description = lines.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn submit_label(mut self, l: &str) -> Self {
        self.submit_label = l.into();
        self
    }
}
