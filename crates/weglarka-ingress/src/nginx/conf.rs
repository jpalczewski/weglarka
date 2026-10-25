//! Small indenting writer for `nginx.conf`.

/// Small builder with indentation (4 spaces).
#[derive(Default)]
pub(super) struct Conf {
    buf: String,
    depth: usize,
}

impl Conf {
    pub(super) fn line(&mut self, text: &str) {
        for _ in 0..self.depth {
            self.buf.push_str("    ");
        }
        self.buf.push_str(text);
        self.buf.push('\n');
    }

    pub(super) fn blank(&mut self) {
        self.buf.push('\n');
    }

    pub(super) fn block(&mut self, header: &str, body: impl FnOnce(&mut Self)) {
        self.line(&format!("{header} {{"));
        self.depth += 1;
        body(self);
        self.depth -= 1;
        self.line("}");
    }

    pub(super) fn finish(self) -> String {
        self.buf
    }
}
