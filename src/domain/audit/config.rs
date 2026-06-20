use serde::{Deserialize, Serialize};

use super::file_sink::FileSink;
use super::kinesis_sink::KinesisFirehoseSink;
use super::pubsub_sink::GcpPubSubSink;
use super::sink::AuditSink;
use super::stdout_sink::StdoutSink;

/// Audit logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Buffer capacity for the async channel (default 10_000).
    #[serde(default = "default_buffer_capacity")]
    pub buffer_capacity: usize,

    /// Configured sinks (at least one; defaults to stdout).
    #[serde(default = "default_sinks")]
    pub sinks: Vec<SinkConfig>,
}

/// Configuration for a specific audit sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SinkConfig {
    #[serde(rename = "stdout")]
    Stdout,

    #[serde(rename = "file")]
    File {
        path: String,
        max_size_mb: u64,
        max_files: u32,
    },

    #[serde(rename = "kinesis_firehose")]
    KinesisFirehose {
        stream_name: String,
        region: String,
    },

    #[serde(rename = "gcp_pubsub")]
    GcpPubSub {
        project: String,
        topic: String,
    },
}

fn default_buffer_capacity() -> usize {
    10_000
}

fn default_sinks() -> Vec<SinkConfig> {
    vec![SinkConfig::Stdout]
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: default_buffer_capacity(),
            sinks: default_sinks(),
        }
    }
}

/// Instantiate concrete sinks from the audit configuration.
///
/// For each `SinkConfig` variant, the corresponding sink implementation is created.
/// If a sink fails to initialize (e.g., file path is invalid), a warning is logged
/// and that sink is skipped.
pub async fn build_sinks(config: &AuditConfig) -> Vec<Box<dyn AuditSink>> {
    let mut sinks: Vec<Box<dyn AuditSink>> = Vec::new();

    for sink_config in &config.sinks {
        match sink_config {
            SinkConfig::Stdout => {
                sinks.push(Box::new(StdoutSink::new()));
            }
            SinkConfig::File {
                path,
                max_size_mb,
                max_files,
            } => match FileSink::new(path.clone(), *max_size_mb, *max_files) {
                Ok(file_sink) => {
                    sinks.push(Box::new(file_sink));
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path,
                        error = %e,
                        "failed to create file audit sink, skipping"
                    );
                }
            },
            SinkConfig::KinesisFirehose {
                stream_name,
                region,
            } => {
                let kinesis_sink =
                    KinesisFirehoseSink::new(stream_name.clone(), region.clone()).await;
                sinks.push(Box::new(kinesis_sink));
            }
            SinkConfig::GcpPubSub { project, topic } => {
                let pubsub_sink = GcpPubSubSink::new(project.clone(), topic.clone());
                sinks.push(Box::new(pubsub_sink));
            }
        }
    }

    sinks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_audit_config() {
        let config = AuditConfig::default();
        assert_eq!(config.buffer_capacity, 10_000);
        assert_eq!(config.sinks.len(), 1);
        assert!(matches!(config.sinks[0], SinkConfig::Stdout));
    }

    #[test]
    fn test_sink_config_stdout_toml_roundtrip() {
        let config = AuditConfig {
            buffer_capacity: 5000,
            sinks: vec![SinkConfig::Stdout],
        };
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: AuditConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.buffer_capacity, 5000);
        assert_eq!(parsed.sinks.len(), 1);
        assert!(matches!(parsed.sinks[0], SinkConfig::Stdout));
    }

    #[test]
    fn test_sink_config_file_toml_roundtrip() {
        let config = AuditConfig {
            buffer_capacity: 10_000,
            sinks: vec![SinkConfig::File {
                path: "/var/log/audit.jsonl".to_string(),
                max_size_mb: 100,
                max_files: 10,
            }],
        };
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: AuditConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.sinks.len(), 1);
        match &parsed.sinks[0] {
            SinkConfig::File {
                path,
                max_size_mb,
                max_files,
            } => {
                assert_eq!(path, "/var/log/audit.jsonl");
                assert_eq!(*max_size_mb, 100);
                assert_eq!(*max_files, 10);
            }
            _ => panic!("expected File sink config"),
        }
    }

    #[test]
    fn test_sink_config_kinesis_toml_roundtrip() {
        let config = AuditConfig {
            buffer_capacity: 10_000,
            sinks: vec![SinkConfig::KinesisFirehose {
                stream_name: "my-stream".to_string(),
                region: "us-east-1".to_string(),
            }],
        };
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: AuditConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.sinks.len(), 1);
        match &parsed.sinks[0] {
            SinkConfig::KinesisFirehose {
                stream_name,
                region,
            } => {
                assert_eq!(stream_name, "my-stream");
                assert_eq!(region, "us-east-1");
            }
            _ => panic!("expected KinesisFirehose sink config"),
        }
    }

    #[test]
    fn test_sink_config_gcp_pubsub_toml_roundtrip() {
        let config = AuditConfig {
            buffer_capacity: 10_000,
            sinks: vec![SinkConfig::GcpPubSub {
                project: "my-project".to_string(),
                topic: "audit-topic".to_string(),
            }],
        };
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: AuditConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.sinks.len(), 1);
        match &parsed.sinks[0] {
            SinkConfig::GcpPubSub { project, topic } => {
                assert_eq!(project, "my-project");
                assert_eq!(topic, "audit-topic");
            }
            _ => panic!("expected GcpPubSub sink config"),
        }
    }

    #[test]
    fn test_toml_deserialization_with_defaults() {
        let toml_str = "";
        let config: AuditConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.buffer_capacity, 10_000);
        assert_eq!(config.sinks.len(), 1);
        assert!(matches!(config.sinks[0], SinkConfig::Stdout));
    }

    #[test]
    fn test_multiple_sinks_toml_roundtrip() {
        let config = AuditConfig {
            buffer_capacity: 20_000,
            sinks: vec![
                SinkConfig::Stdout,
                SinkConfig::File {
                    path: "/tmp/audit.jsonl".to_string(),
                    max_size_mb: 50,
                    max_files: 5,
                },
                SinkConfig::KinesisFirehose {
                    stream_name: "stream".to_string(),
                    region: "eu-west-1".to_string(),
                },
                SinkConfig::GcpPubSub {
                    project: "proj".to_string(),
                    topic: "topic".to_string(),
                },
            ],
        };
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: AuditConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.buffer_capacity, 20_000);
        assert_eq!(parsed.sinks.len(), 4);
    }

    #[tokio::test]
    async fn test_build_sinks_stdout() {
        let config = AuditConfig {
            buffer_capacity: 10_000,
            sinks: vec![SinkConfig::Stdout],
        };
        let sinks = build_sinks(&config).await;
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].name(), "stdout");
    }

    #[tokio::test]
    async fn test_build_sinks_skips_invalid_file_path() {
        let config = AuditConfig {
            buffer_capacity: 10_000,
            sinks: vec![
                SinkConfig::Stdout,
                SinkConfig::File {
                    // Use a path that should fail (read-only or nonexistent deep path)
                    path: "/nonexistent/deeply/nested/path/that/should/fail/audit.jsonl"
                        .to_string(),
                    max_size_mb: 100,
                    max_files: 10,
                },
            ],
        };
        let sinks = build_sinks(&config).await;
        // File sink should be skipped due to invalid path, leaving only stdout
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].name(), "stdout");
    }
}
