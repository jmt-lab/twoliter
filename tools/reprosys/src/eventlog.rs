//! A JSON Lines log of every comparison step, with `time_ms`, `event`,
//! `region` and the event's fields. Only the thread that opened it logs.

use crate::error::Result;
use serde_json::{Map, Value};
use snafu::ResultExt;
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
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

/// Start appending events to `path`.
pub fn open(path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .whatever_context(format!("failed to open {}", path.display()))?;
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

/// Log `event` with `fields`, which should be a JSON object.
pub fn event(event: &str, fields: Value) {
    with_log(|log| {
        if let Some(log) = log.as_mut().filter(|log| log.error.is_none()) {
            write_event(log, event, fields);
        }
    })
}

fn write_event(log: &mut Log, event: &str, fields: Value) {
    let time_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let fields = match fields {
        Value::Object(fields) => fields,
        Value::Null => Map::new(),
        other => Map::from_iter([("value".to_string(), other)]),
    };
    // Common fields first, then the event's.
    let line = (|| -> serde_json::Result<String> {
        let mut line = format!(
            "{{\"time_ms\":{time_ms},\"event\":{},\"region\":{}",
            serde_json::to_string(event)?,
            serde_json::to_string(&log.region)?
        );
        let fields = serde_json::to_string(&fields)?;
        if fields != "{}" {
            line.push(',');
            line.push_str(&fields[1..]);
        } else {
            line.push('}');
        }
        line.push('\n');
        Ok(line)
    })();
    let result = line
        .map_err(std::io::Error::from)
        .and_then(|line| log.out.write_all(line.as_bytes()));
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
    use serde_json::json;

    #[test]
    fn writes_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        std::fs::write(&path, "{\"event\":\"earlier\"}\n").unwrap();
        // Logging is off until opened.
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
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert_eq!(lines[0]["event"], "earlier");
        assert_eq!(lines[1]["event"], "entry");
        assert_eq!(lines[1]["region"], "ROOT-A");
        assert_eq!(lines[1]["path"], "/etc");
        assert!(lines[1]["time_ms"].as_u64().unwrap() > 0);
        assert_eq!(lines[2]["region"], Value::Null);
        assert_eq!(lines[3]["event"], "empty");
        // The common fields come first.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.lines().nth(1).unwrap().starts_with("{\"time_ms\":"),
            "{text}"
        );
        assert!(
            text.contains(",\"event\":\"entry\",\"region\":\"ROOT-A\",\"path\":\"/etc\"}"),
            "{text}"
        );
    }
}
