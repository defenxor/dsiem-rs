use tracing::{ metadata::LevelFilter, Subscriber };
use tracing_subscriber::{ Layer, Registry, prelude::__tracing_subscriber_SubscriberExt };

pub fn setup_logger_json(log_severity: LevelFilter) -> std::io::Result<impl Subscriber> {
    let stdout_log = tracing_subscriber::fmt::layer().json().with_filter(log_severity);
    let subscriber = Registry::default().with(stdout_log);
    Ok(subscriber)
}

pub fn setup_logger(log_severity: LevelFilter) -> std::io::Result<impl Subscriber> {
    let stdout_log = tracing_subscriber::fmt::layer().with_filter(log_severity);
    let subscriber = Registry::default().with(stdout_log);
    Ok(subscriber)
}

pub fn verbosity_to_level_filter(severity: u8) -> LevelFilter {
    match severity {
        0 => LevelFilter::INFO,
        1 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_logging() {
        let level = verbosity_to_level_filter(10);
        assert!(level == LevelFilter::TRACE);
        let level = verbosity_to_level_filter(0);
        assert!(level == LevelFilter::INFO);
        let level = verbosity_to_level_filter(1);
        assert!(level == LevelFilter::DEBUG);
        {
            let sub = setup_logger_json(level).unwrap();
            let _g = tracing::subscriber::set_default(sub);
        }
        {
            let sub = setup_logger(level).unwrap();
            let _g = tracing::subscriber::set_default(sub);
        }
    }
}
