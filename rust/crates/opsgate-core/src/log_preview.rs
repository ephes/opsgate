//! Bounded views of retained step logs (`rust/PLAN.md` 4.12), ported from
//! `src/opsgate/log_preview.py`: the preview on the ticket page and in the
//! runner's `summary_markdown` (`read_tail_lines`) and the step log page
//! (`read_step_log`). Pinned by `rust/fixtures/log_preview.json`.
//!
//! Undecodable bytes become U+FFFD per maximal invalid subsequence, the
//! replacement policy of both Python's `errors="replace"` and
//! [`String::from_utf8_lossy`].

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// The preview reads at most the final 64 KiB.
pub const TAIL_BYTE_LIMIT: u64 = 64 * 1024;
/// Each preview line keeps its final 2048 bytes.
pub const LINE_BYTE_LIMIT: usize = 2048;
/// First preview line when bytes or lines were omitted.
pub const TRUNCATION_MARKER: &str = "[log preview truncated]";
/// Lines of the ticket-page preview and of `summary_markdown`.
pub const PREVIEW_LINE_LIMIT: usize = 40;
/// The step log page reads at most the final 2 MiB.
pub const STEP_LOG_BYTE_LIMIT: u64 = 2 * 1024 * 1024;
/// Prefix of a step log whose earlier bytes were omitted.
pub const STEP_LOG_TRUNCATION_MARKER: &str = "[step log truncated]";

/// The byte limits, as parameters so tests can use small windows like the
/// Python tests do by patching the module constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub tail_bytes: u64,
    pub line_bytes: usize,
    pub step_log_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            tail_bytes: TAIL_BYTE_LIMIT,
            line_bytes: LINE_BYTE_LIMIT,
            step_log_bytes: STEP_LOG_BYTE_LIMIT,
        }
    }
}

/// Open a file for reading like Python's `open(path, "rb")`: a directory is
/// an error (`IsADirectoryError`) instead of a readable handle.
fn open_regular(path: &Path) -> io::Result<File> {
    let file = File::open(path)?;
    if file.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::IsADirectory,
            "is a directory",
        ));
    }
    Ok(file)
}

/// The final `limit` bytes of the file and whether earlier bytes exist.
fn read_tail(path: &Path, limit: u64) -> io::Result<(Vec<u8>, bool)> {
    let mut file = open_regular(path)?;
    let size = file.seek(SeekFrom::End(0))?;
    let start = size.saturating_sub(limit);
    file.seek(SeekFrom::Start(start))?;
    let mut data = Vec::new();
    file.take(limit).read_to_end(&mut data)?;
    Ok((data, start > 0))
}

/// `read_tail_lines(path, max_lines)`: the last `max_lines` lines of the
/// final 64 KiB (newlines normalised, a trailing empty line dropped, each
/// line cut to its final 2048 bytes), with [`TRUNCATION_MARKER`] first when
/// anything was omitted. A missing file has no lines; other read errors are
/// returned (Python lets them propagate).
pub fn read_tail_lines(path: &Path, max_lines: usize) -> io::Result<Vec<String>> {
    read_tail_lines_with(path, max_lines, Limits::default())
}

/// [`read_tail_lines`] with explicit limits.
pub fn read_tail_lines_with(
    path: &Path,
    max_lines: usize,
    limits: Limits,
) -> io::Result<Vec<String>> {
    if max_lines == 0 {
        return Ok(Vec::new());
    }
    let (data, omitted_bytes) = match read_tail(path, limits.tail_bytes) {
        Ok(tail) => tail,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    Ok(tail_lines(
        &data,
        omitted_bytes,
        max_lines,
        limits.line_bytes,
    ))
}

/// The pure part of [`read_tail_lines`] over an already read window.
fn tail_lines(
    data: &[u8],
    omitted_bytes: bool,
    max_lines: usize,
    line_bytes: usize,
) -> Vec<String> {
    let normalised = normalise_newlines(data);
    let mut lines: Vec<&[u8]> = normalised.split(|byte| *byte == b'\n').collect();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    let mut truncated = omitted_bytes || lines.len() > max_lines;
    let first = lines.len().saturating_sub(max_lines);
    let mut result = Vec::with_capacity(max_lines + 1);
    for line in &lines[first..] {
        let line = if line.len() > line_bytes {
            truncated = true;
            &line[line.len() - line_bytes..]
        } else {
            line
        };
        result.push(String::from_utf8_lossy(line).into_owned());
    }
    if truncated {
        result.insert(0, TRUNCATION_MARKER.to_owned());
    }
    result
}

/// `\r\n` → `\n`, then `\r` → `\n` (bytes).
fn normalise_newlines(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut index = 0;
    while index < data.len() {
        match data[index] {
            b'\r' => {
                out.push(b'\n');
                if data.get(index + 1) == Some(&b'\n') {
                    index += 1;
                }
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    out
}

/// `read_step_log(path)`: the final 2 MiB decoded with replacement, newlines
/// normalised, `[step log truncated]\n` prepended when earlier bytes were
/// omitted. Every read error is returned, including a missing file.
pub fn read_step_log(path: &Path) -> io::Result<String> {
    read_step_log_with(path, Limits::default())
}

/// [`read_step_log`] with explicit limits.
pub fn read_step_log_with(path: &Path, limits: Limits) -> io::Result<String> {
    let (data, omitted_bytes) = read_tail(path, limits.step_log_bytes)?;
    // Python decodes first and normalises the text; `\r` and `\n` never
    // occur inside a replaced sequence, so normalising the bytes first is the
    // same.
    let text = String::from_utf8_lossy(&normalise_newlines(&data)).into_owned();
    Ok(if omitted_bytes {
        format!("{STEP_LOG_TRUNCATION_MARKER}\n{text}")
    } else {
        text
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newline_normalisation() {
        assert_eq!(normalise_newlines(b"a\r\nb\rc\r\r\n"), b"a\nb\nc\n\n");
    }

    #[test]
    fn directory_is_an_error_not_an_empty_preview() {
        let directory = tempfile::tempdir().unwrap();
        assert!(read_tail_lines(directory.path(), 40).is_err());
        assert!(read_step_log(directory.path()).is_err());
    }

    #[test]
    fn missing_file() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.log");
        assert_eq!(read_tail_lines(&missing, 40).unwrap(), Vec::<String>::new());
        assert_eq!(
            read_step_log(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
