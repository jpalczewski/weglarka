//! Wypisywanie wyników: `--json` = jeden dokument JSON na stdout; tekst dla ludzi poza tym.
//! Błędy zawsze na stderr (w trybie `--json` jako `{"error":{...}}`).

use serde::Serialize;

use crate::error::CliError;

pub fn emit<T: Serialize>(json: bool, value: &T, text: impl FnOnce() -> String) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(value).expect("serializable output")
        );
    } else {
        let text = text();
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }
    }
}

pub fn emit_error(json: bool, err: &CliError) {
    if json {
        eprintln!(
            "{}",
            serde_json::to_string(&err.envelope()).expect("serializable error")
        );
    } else {
        eprintln!("error: {}", err.message);
        if let Some(hint) = &err.hint {
            eprintln!("hint: {hint}");
        }
    }
}

/// Prosta tabela z wyrównanymi kolumnami (ostatnia kolumna bez dopełnienia).
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let last = cells.len() - 1;
        let mut out = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i == last {
                out.push_str(cell);
            } else {
                out.push_str(&format!("{cell:<w$}  ", w = widths[i]));
            }
        }
        out.push('\n');
        out
    };
    let mut out = line(header.to_vec());
    for row in rows {
        out.push_str(&line(row.iter().map(String::as_str).collect()));
    }
    out
}
