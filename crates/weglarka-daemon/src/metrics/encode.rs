//! Prometheus text exposition format (0.0.4), written by hand: the values are computed at scrape
//! time, so a metrics library's registry would only copy them (ADR 0061, decision 9).
//!
//! The encoder knows nothing about where a value comes from. A source returns [`Family`] values and
//! [`encode`] turns them into text with `# HELP`/`# TYPE` lines, escaped label values and a stable order
//! (families by name, samples by label set), so a snapshot of the output does not flap.

use std::fmt::Write as _;

/// `Content-Type` of the text format.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Counter,
    Gauge,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
        }
    }
}

/// One time series: label pairs (written in the given order) and a value.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub labels: Vec<(&'static str, String)>,
    pub value: f64,
}

impl Sample {
    pub fn new(labels: Vec<(&'static str, String)>, value: f64) -> Self {
        Self { labels, value }
    }
}

/// A metric name with its help text, type and samples.
#[derive(Debug, Clone, PartialEq)]
pub struct Family {
    pub name: &'static str,
    pub help: &'static str,
    pub kind: Kind,
    pub samples: Vec<Sample>,
}

/// Encodes `families` into the text format. Families with no samples are omitted.
pub fn encode(mut families: Vec<Family>) -> String {
    families.sort_by(|a, b| a.name.cmp(b.name));
    let mut out = String::new();
    for mut family in families {
        if family.samples.is_empty() {
            continue;
        }
        debug_assert!(valid_name(family.name), "bad metric name {}", family.name);
        family.samples.sort_by(|a, b| a.labels.cmp(&b.labels));
        let _ = writeln!(out, "# HELP {} {}", family.name, escape_help(family.help));
        let _ = writeln!(out, "# TYPE {} {}", family.name, family.kind.as_str());
        for sample in &family.samples {
            out.push_str(family.name);
            if !sample.labels.is_empty() {
                out.push('{');
                for (i, (name, value)) in sample.labels.iter().enumerate() {
                    debug_assert!(valid_name(name), "bad label name {name}");
                    if i > 0 {
                        out.push(',');
                    }
                    let _ = write!(out, "{name}=\"{}\"", escape_label(value));
                }
                out.push('}');
            }
            let _ = writeln!(out, " {}", format_value(sample.value));
        }
    }
    out
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Label values escape `\`, `"` and newline.
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Help text escapes `\` and newline.
fn escape_help(help: &str) -> String {
    help.replace('\\', "\\\\").replace('\n', "\\n")
}

fn format_value(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value.is_infinite() {
        if value > 0.0 { "+Inf" } else { "-Inf" }.to_owned()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labelled(pairs: &[(&'static str, &str)], value: f64) -> Sample {
        Sample::new(
            pairs.iter().map(|(k, v)| (*k, (*v).to_owned())).collect(),
            value,
        )
    }

    #[test]
    fn exposition_text_is_sorted_and_escaped() {
        let text = encode(vec![
            Family {
                name: "weglarka_zeta_total",
                help: "Second family, listed first.",
                kind: Kind::Counter,
                samples: vec![Sample::new(Vec::new(), 7.0)],
            },
            Family {
                name: "weglarka_alpha",
                help: "Help with a \\ backslash\nand a newline.",
                kind: Kind::Gauge,
                samples: vec![
                    labelled(&[("app", "web"), ("role", "retiring")], 1.5),
                    labelled(&[("app", "web"), ("role", "active")], 2.0),
                    labelled(&[("app", "quo\"te\\back\nline")], f64::NAN),
                    labelled(&[("app", "inf")], f64::INFINITY),
                ],
            },
            Family {
                name: "weglarka_empty",
                help: "Omitted: no samples.",
                kind: Kind::Gauge,
                samples: Vec::new(),
            },
        ]);
        insta::assert_snapshot!(text);
    }

    #[test]
    fn output_does_not_depend_on_input_order() {
        let a = Family {
            name: "weglarka_a",
            help: "a",
            kind: Kind::Gauge,
            samples: vec![
                labelled(&[("app", "x")], 1.0),
                labelled(&[("app", "y")], 2.0),
            ],
        };
        let mut b = a.clone();
        b.samples.reverse();
        assert_eq!(encode(vec![a]), encode(vec![b]));
    }
}
