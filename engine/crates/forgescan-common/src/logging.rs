//! Logging configuration using tracing

use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Log format options
#[derive(Debug, Clone, Copy, Default)]
pub enum LogFormat {
    /// Human-readable format (default for development)
    #[default]
    Pretty,
    /// JSON format (for production/log aggregation)
    Json,
    /// Compact single-line format
    Compact,
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Minimum log level (default: info)
    pub level: String,
    /// Log format
    pub format: LogFormat,
    /// Include span events (enter/exit)
    pub with_spans: bool,
    /// Include file/line information
    pub with_file: bool,
    /// Include target (module path)
    pub with_target: bool,
    /// Include thread IDs
    pub with_thread_ids: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: String::from("info"),
            format: LogFormat::Pretty,
            with_spans: false,
            with_file: false,
            with_target: true,
            with_thread_ids: false,
        }
    }
}

impl LogConfig {
    /// Create a new logging configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the log level
    pub fn level(mut self, level: impl Into<String>) -> Self {
        self.level = level.into();
        self
    }

    /// Set the log format
    pub fn format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    /// Enable JSON format
    pub fn json(mut self) -> Self {
        self.format = LogFormat::Json;
        self
    }

    /// Enable span events
    pub fn with_spans(mut self) -> Self {
        self.with_spans = true;
        self
    }

    /// Enable file/line information
    pub fn with_file(mut self) -> Self {
        self.with_file = true;
        self
    }
}

/// Initialize the global tracing subscriber with default settings
pub fn init_logging() {
    init_logging_with_config(LogConfig::default());
}

/// Initialize the global tracing subscriber with custom configuration
pub fn init_logging_with_config(config: LogConfig) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    let span_events = if config.with_spans {
        FmtSpan::NEW | FmtSpan::CLOSE
    } else {
        FmtSpan::NONE
    };

    match config.format {
        LogFormat::Json => {
            let fmt_layer = fmt::layer()
                .json()
                .with_span_events(span_events)
                .with_file(config.with_file)
                .with_line_number(config.with_file)
                .with_target(config.with_target)
                .with_thread_ids(config.with_thread_ids);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
        LogFormat::Compact => {
            let fmt_layer = fmt::layer()
                .compact()
                .with_span_events(span_events)
                .with_file(config.with_file)
                .with_line_number(config.with_file)
                .with_target(config.with_target)
                .with_thread_ids(config.with_thread_ids);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
        LogFormat::Pretty => {
            let fmt_layer = fmt::layer()
                .pretty()
                .with_span_events(span_events)
                .with_file(config.with_file)
                .with_line_number(config.with_file)
                .with_target(config.with_target)
                .with_thread_ids(config.with_thread_ids);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_config_builder() {
        let config = LogConfig::new()
            .level("debug")
            .json()
            .with_spans()
            .with_file();

        assert_eq!(config.level, "debug");
        assert!(matches!(config.format, LogFormat::Json));
        assert!(config.with_spans);
        assert!(config.with_file);
    }
}
