//! The set of characters that must never reach a terminal or a page from untrusted stream text
//! (app logs, access-log fields).
//!
//! Only the *set* lives here. The *treatment* differs per consumer and stays local: the panel drops
//! them, the CLI replaces them with U+FFFD, and each decides for itself what to do with tab and
//! newline (both are control characters, so they are reported as unsafe here).

/// True for a character that is unsafe to show from untrusted text: any control character
/// (NUL, ESC, DEL, the C1 range, tab, newline, carriage return, …) or a bidirectional override,
/// embedding, isolate or directional mark.
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}'
        )
}

#[cfg(test)]
mod tests {
    use super::is_unsafe_char;

    #[test]
    fn controls_are_unsafe() {
        for c in ['\0', '\u{1b}', '\u{7f}', '\u{07}', '\r', '\t', '\n'] {
            assert!(is_unsafe_char(c), "{c:?}");
        }
        for code in 0x80..=0x9f_u32 {
            let c = char::from_u32(code).unwrap();
            assert!(is_unsafe_char(c), "C1 {code:#x}");
        }
    }

    #[test]
    fn every_bidi_mark_is_unsafe() {
        let marks = (0x202a..=0x202e_u32)
            .chain(0x2066..=0x2069)
            .chain([0x200e, 0x200f]);
        let mut count = 0;
        for code in marks {
            assert!(is_unsafe_char(char::from_u32(code).unwrap()), "{code:#x}");
            count += 1;
        }
        assert_eq!(count, 11);
    }

    #[test]
    fn ordinary_text_is_safe() {
        for c in ['a', 'Z', '0', ' ', 'ż', '漢', 'か', '😀', '\u{fffd}', '…'] {
            assert!(!is_unsafe_char(c), "{c:?}");
        }
    }
}
