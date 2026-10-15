//! A JSON Lines log of every comparison step, with `time_ms`, `event`,
//! `region` and the event's fields. Only the thread that opened it logs.

use crate::error::Result;
use serde::Serialize;
use snafu::ResultExt;
use std::cell::RefCell;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

struct Log {
    out: BufWriter<File>,
    region: Option<String>,
    /// The first write error, reported by `close`; later events are dropped.
    error: Option<std::io::Error>,
}

thread_local! {
    static LOG: RefCell<Option<Log>> = const { RefCell::new(None) };
}

fn with_log<T>(f: impl FnOnce(&mut Option<Log>) -> T) -> T {
    LOG.with(|log| f(&mut log.borrow_mut()))
}

/// Start writing events to `path`, replacing its contents.
pub fn open(path: &Path) -> Result<()> {
    let file = File::create(path).whatever_context(format!("failed to open {}", path.display()))?;
    with_log(|log| {
        *log = Some(Log {
            out: BufWriter::new(file),
            region: None,
            error: None,
        })
    });
    Ok(())
}

/// Flush and stop logging.
pub fn close() -> Result<()> {
    let Some(mut log) = with_log(Option::take) else {
        return Ok(());
    };
    if let Some(e) = log.error {
        return Err(e).whatever_context("failed to write the log");
    }
    log.out.flush().whatever_context("failed to write the log")
}

/// Whether events are logged, so that callers can skip work done only for the log.
pub fn enabled() -> bool {
    with_log(|log| log.is_some())
}

/// Log `event` with `fields`, which must serialize as a map.
pub fn event(event: &str, fields: impl Serialize) {
    with_log(|log| {
        if let Some(log) = log.as_mut().filter(|log| log.error.is_none()) {
            write_event(log, event, fields);
        }
    })
}

/// Log an `error` event.
pub fn error(e: impl std::fmt::Display) {
    event("error", serde_json::json!({ "error": e.to_string() }));
}

/// A line of the log: the common fields, then the event's.
#[derive(Serialize)]
struct Line<'a, T> {
    time_ms: u64,
    event: &'a str,
    region: Option<&'a str>,
    #[serde(flatten)]
    fields: T,
}

fn write_event(log: &mut Log, event: &str, fields: impl Serialize) {
    let time_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let line = Line {
        time_ms,
        event,
        region: log.region.as_deref(),
        fields,
    };
    let result = serde_json::to_writer(&mut log.out, &line)
        .map_err(std::io::Error::from)
        .and_then(|()| log.out.write_all(b"\n"));
    if let Err(e) = result {
        log.error = Some(e);
    }
}

/// Tags events with a region until it is dropped.
#[must_use]
pub struct RegionScope(Option<String>);

/// Tag the events logged until the returned scope is dropped with `name`.
pub fn region(name: &str) -> RegionScope {
    RegionScope(with_log(|log| {
        log.as_mut()
            .and_then(|log| log.region.replace(name.to_string()))
    }))
}

impl Drop for RegionScope {
    fn drop(&mut self) {
        let previous = self.0.take();
        with_log(|log| {
            if let Some(log) = log.as_mut() {
                log.region = previous;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn writes_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        std::fs::write(&path, "{\"event\":\"earlier\"}\n").unwrap();
        // Logging is off until opened, which replaces earlier events.
        event("dropped", json!({}));
        open(&path).unwrap();
        assert!(enabled());
        {
            let _scope = region("ROOT-A");
            event("entry", json!({"path": "/etc"}));
        }
        event("verdict", json!({"verdict": "verified"}));
        event("empty", json!({}));
        close().unwrap();
        assert!(!enabled());

        let lines: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert_eq!(lines[0]["event"], "entry");
        assert_eq!(lines[0]["region"], "ROOT-A");
        assert_eq!(lines[0]["path"], "/etc");
        assert!(lines[0]["time_ms"].as_u64().unwrap() > 0);
        assert_eq!(lines[1]["region"], Value::Null);
        assert_eq!(lines[2]["event"], "empty");
        // The common fields come first.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("{\"time_ms\":"), "{text}");
        assert!(
            text.contains(",\"event\":\"entry\",\"region\":\"ROOT-A\",\"path\":\"/etc\"}"),
            "{text}"
        );
    }
}
