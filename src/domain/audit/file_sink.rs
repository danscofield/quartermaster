use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::schema::AuditEnvelope;
use super::sink::{AuditSink, SinkError};

/// A sink that writes JSON-serialized audit events to a rotating log file.
///
/// Events are line-buffered (one JSON object per line). When the file exceeds
/// `max_size_mb`, it is rotated: the current file is renamed to `.1`, existing
/// rotated files are shifted (`.1` → `.2`, etc.), and files beyond `max_files`
/// are deleted.
pub struct FileSink {
    state: Mutex<FileSinkState>,
    path: PathBuf,
    max_size_bytes: u64,
    max_files: u32,
}

struct FileSinkState {
    writer: BufWriter<File>,
    current_size: u64,
}

impl FileSink {
    /// Create a new `FileSink` that writes to the given path.
    ///
    /// - `path`: File path for the audit log (e.g. `/var/log/quartermaster/audit.jsonl`)
    /// - `max_size_mb`: Maximum file size in megabytes before rotation
    /// - `max_files`: Maximum number of rotated files to keep
    pub fn new(path: String, max_size_mb: u64, max_files: u32) -> Result<Self, SinkError> {
        let path_buf = PathBuf::from(&path);

        // Ensure parent directory exists
        if let Some(parent) = path_buf.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                SinkError::with_source(
                    format!("failed to create directory for audit log: {}", parent.display()),
                    e,
                )
            })?;
        }

        let (file, current_size) = Self::open_file(&path_buf)?;
        let writer = BufWriter::new(file);

        Ok(Self {
            state: Mutex::new(FileSinkState {
                writer,
                current_size,
            }),
            path: path_buf,
            max_size_bytes: max_size_mb * 1024 * 1024,
            max_files,
        })
    }

    /// Open (or create) the log file and return it along with its current size.
    fn open_file(path: &Path) -> Result<(File, u64), SinkError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                SinkError::with_source(
                    format!("failed to open audit log file: {}", path.display()),
                    e,
                )
            })?;

        let current_size = file.metadata().map(|m| m.len()).unwrap_or(0);

        Ok((file, current_size))
    }

    /// Rotate log files: current → .1, .1 → .2, ..., delete beyond max_files.
    fn rotate(&self, state: &mut FileSinkState) -> Result<(), SinkError> {
        // Flush and drop the current writer so the file handle is released
        state.writer.flush().map_err(|e| {
            SinkError::with_source("failed to flush before rotation", e)
        })?;

        // Shift existing rotated files
        // Delete the oldest if it exceeds max_files
        let oldest = self.rotated_path(self.max_files);
        if oldest.exists() {
            fs::remove_file(&oldest).map_err(|e| {
                SinkError::with_source(
                    format!("failed to remove oldest rotated file: {}", oldest.display()),
                    e,
                )
            })?;
        }

        // Shift .N-1 → .N, .N-2 → .N-1, ..., .1 → .2
        for i in (1..self.max_files).rev() {
            let from = self.rotated_path(i);
            let to = self.rotated_path(i + 1);
            if from.exists() {
                fs::rename(&from, &to).map_err(|e| {
                    SinkError::with_source(
                        format!("failed to rotate {} → {}", from.display(), to.display()),
                        e,
                    )
                })?;
            }
        }

        // Rename current file to .1
        let first_rotated = self.rotated_path(1);
        if self.path.exists() {
            fs::rename(&self.path, &first_rotated).map_err(|e| {
                SinkError::with_source(
                    format!(
                        "failed to rotate current file {} → {}",
                        self.path.display(),
                        first_rotated.display()
                    ),
                    e,
                )
            })?;
        }

        // Open a fresh file
        let (file, current_size) = Self::open_file(&self.path)?;
        state.writer = BufWriter::new(file);
        state.current_size = current_size;

        Ok(())
    }

    /// Build path for the Nth rotated file (e.g. `/var/log/audit.jsonl.1`).
    fn rotated_path(&self, n: u32) -> PathBuf {
        let mut p = self.path.as_os_str().to_owned();
        p.push(format!(".{}", n));
        PathBuf::from(p)
    }
}

#[async_trait]
impl AuditSink for FileSink {
    async fn send_batch(&self, events: &[AuditEnvelope]) -> Result<(), SinkError> {
        let mut state = self.state.lock().await;

        for event in events {
            let json = serde_json::to_string(event).map_err(|e| {
                SinkError::with_source("failed to serialize audit event", e)
            })?;

            let line = format!("{}\n", json);
            let line_bytes = line.as_bytes();
            let line_len = line_bytes.len() as u64;

            // Check if writing this line would exceed the max size
            if state.current_size + line_len > self.max_size_bytes && state.current_size > 0 {
                self.rotate(&mut state)?;
            }

            state.writer.write_all(line_bytes).map_err(|e| {
                SinkError::with_source("failed to write audit event to file", e)
            })?;
            state.current_size += line_len;
        }

        // Line-buffered: flush after each batch
        state.writer.flush().map_err(|e| {
            SinkError::with_source("failed to flush audit log file", e)
        })?;

        Ok(())
    }

    async fn flush(&self) -> Result<(), SinkError> {
        let mut state = self.state.lock().await;
        state.writer.flush().map_err(|e| {
            SinkError::with_source("failed to flush audit log file", e)
        })?;
        Ok(())
    }

    fn name(&self) -> &str {
        "file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::domain::audit::schema::{AuditActor, AuditEnvelope, Outcome};
    use std::fs;

    fn make_test_event(id: &str) -> AuditEnvelope {
        AuditEnvelope {
            schema_version: "1.0".to_string(),
            event_type: "token.exchange.success".to_string(),
            timestamp: Utc::now(),
            request_id: id.to_string(),
            actor: AuditActor {
                subject: "test-subject".to_string(),
                source_type: "spire".to_string(),
            },
            details: serde_json::json!({"test": true}),
            outcome: Outcome::Success,
            error: None,
        }
    }

    /// Create a unique temporary directory for tests.
    fn test_tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("quartermaster_file_sink_tests")
            .join(name)
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn test_file_sink_writes_json_lines() {
        let tmp_dir = test_tmp_dir("writes_json_lines");
        let log_path = tmp_dir.join("audit.jsonl");

        let sink = FileSink::new(
            log_path.to_str().unwrap().to_string(),
            10, // 10 MB
            3,
        )
        .unwrap();

        let events = vec![make_test_event("req-1"), make_test_event("req-2")];
        sink.send_batch(&events).await.unwrap();

        let content = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify each line is valid JSON
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["schema_version"], "1.0");
        }

        // Cleanup
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn test_file_sink_name() {
        let tmp_dir = test_tmp_dir("name");
        let log_path = tmp_dir.join("audit.jsonl");

        let sink = FileSink::new(
            log_path.to_str().unwrap().to_string(),
            10,
            3,
        )
        .unwrap();

        assert_eq!(sink.name(), "file");

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn test_file_sink_flush() {
        let tmp_dir = test_tmp_dir("flush");
        let log_path = tmp_dir.join("audit.jsonl");

        let sink = FileSink::new(
            log_path.to_str().unwrap().to_string(),
            10,
            3,
        )
        .unwrap();

        let events = vec![make_test_event("req-flush")];
        sink.send_batch(&events).await.unwrap();
        sink.flush().await.unwrap();

        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("req-flush"));

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn test_file_sink_rotation_triggers_at_boundary() {
        let tmp_dir = test_tmp_dir("rotation_boundary");
        let log_path = tmp_dir.join("audit.jsonl");

        // Use a very small max size to trigger rotation quickly
        // With max_size_bytes = 0, after the first event makes current_size > 0,
        // the next event will trigger rotation
        let sink = FileSink::new(
            log_path.to_str().unwrap().to_string(),
            0, // 0 MB means max_size_bytes = 0, rotation on every write after the first
            3,
        )
        .unwrap();

        sink.send_batch(&[make_test_event("event-1")]).await.unwrap();
        sink.send_batch(&[make_test_event("event-2")]).await.unwrap();
        sink.send_batch(&[make_test_event("event-3")]).await.unwrap();

        // The current file should contain the latest event
        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("event-3"));

        // Rotated file .1 should exist with the previous event
        let rotated_1 = tmp_dir.join("audit.jsonl.1");
        assert!(rotated_1.exists());
        let rotated_content = fs::read_to_string(&rotated_1).unwrap();
        assert!(rotated_content.contains("event-2"));

        // Rotated file .2 should exist with the first event
        let rotated_2 = tmp_dir.join("audit.jsonl.2");
        assert!(rotated_2.exists());
        let rotated_content_2 = fs::read_to_string(&rotated_2).unwrap();
        assert!(rotated_content_2.contains("event-1"));

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn test_file_sink_rotation_deletes_old_files() {
        let tmp_dir = test_tmp_dir("rotation_deletes");
        let log_path = tmp_dir.join("audit.jsonl");

        // max_files = 2, so only .1 and .2 should survive
        let sink = FileSink::new(
            log_path.to_str().unwrap().to_string(),
            0, // trigger rotation on every write
            2,
        )
        .unwrap();

        // Write 5 events, each triggering a rotation after the first
        for i in 1..=5 {
            sink.send_batch(&[make_test_event(&format!("event-{}", i))])
                .await
                .unwrap();
        }

        // Current file should have the latest event
        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("event-5"));

        // .1 should exist
        let rotated_1 = tmp_dir.join("audit.jsonl.1");
        assert!(rotated_1.exists());

        // .2 should exist
        let rotated_2 = tmp_dir.join("audit.jsonl.2");
        assert!(rotated_2.exists());

        // .3 should NOT exist (max_files = 2)
        let rotated_3 = tmp_dir.join("audit.jsonl.3");
        assert!(!rotated_3.exists());

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn test_file_sink_creates_parent_directory() {
        let tmp_dir = test_tmp_dir("creates_parent");
        let log_path = tmp_dir.join("nested").join("dir").join("audit.jsonl");

        let sink = FileSink::new(
            log_path.to_str().unwrap().to_string(),
            10,
            3,
        )
        .unwrap();

        sink.send_batch(&[make_test_event("nested-test")]).await.unwrap();

        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("nested-test"));

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
