//! The two Python `str` behaviours the settings and the env-file loader rely
//! on (`rust/PLAN.md` 4.2): `str.strip()` without arguments and the line
//! boundaries of `str.splitlines()`.

/// Python's `str.isspace()`: Unicode `White_Space` plus the four ASCII
/// information separators U+001C..U+001F, which CPython also treats as
/// whitespace (bidirectional class B/S).
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// Python's `str.strip()` (no argument).
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// The line boundaries of Python's `str.splitlines()`.
pub fn is_line_boundary(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\u{0b}'
            | '\u{0c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[hex(c) for c in range(0x110000) if chr(c).isspace()]` (CPython 3.11-3.15).
    const PYTHON_SPACE: &[u32] = &[
        0x9, 0xa, 0xb, 0xc, 0xd, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001,
        0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029,
        0x202f, 0x205f, 0x3000,
    ];

    /// Characters `c` for which `("a" + c + "b").splitlines()` has two parts.
    const PYTHON_LINE_BOUNDARY: &[u32] =
        &[0xa, 0xb, 0xc, 0xd, 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029];

    #[test]
    fn whitespace_set_is_pythons() {
        let ours: Vec<u32> = (0..=0x10ffff_u32)
            .filter_map(char::from_u32)
            .filter(|c| is_space(*c))
            .map(u32::from)
            .collect();
        assert_eq!(ours, PYTHON_SPACE);
    }

    #[test]
    fn line_boundaries_are_pythons() {
        let ours: Vec<u32> = (0..=0x10ffff_u32)
            .filter_map(char::from_u32)
            .filter(|c| is_line_boundary(*c))
            .map(u32::from)
            .collect();
        assert_eq!(ours, PYTHON_LINE_BOUNDARY);
    }

    #[test]
    fn strip_removes_python_whitespace_only_at_the_ends() {
        assert_eq!(strip("\u{1c}\u{3000} a b\u{a0}\u{1f}"), "a b");
        assert_eq!(strip("\u{feff}a"), "\u{feff}a");
        assert_eq!(strip("\u{180e}a"), "\u{180e}a");
        assert_eq!(strip(" \t\n "), "");
    }
}
