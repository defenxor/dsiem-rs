use std::{collections::HashMap, time::Duration};

use opentelemetry::{propagation::TextMapPropagator, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    propagation::TraceContextPropagator,
    trace::{self, RandomIdGenerator, Sampler},
    Resource,
};

use anyhow::Result;
use tracing::{metadata::LevelFilter, Span, Subscriber};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{filter, layer::SubscriberExt, Registry};

use crate::event::NormalizedEvent;

pub const OTLP_TIMEOUT_SECONDS: u64 = 10;

#[derive(PartialEq)]
pub enum LogType {
    Json,
    Plain,
}

#[derive(Clone, Default)]
pub struct OtelConfig {
    pub otlp_endpoint: String,
    pub service_name: String,
    pub tracing_enabled: bool,
    pub metrics_enabled: bool,
}

pub fn setup(
    verbosity: u8,
    log_format: LogType,
    otel_config: OtelConfig,
) -> Result<impl Subscriber> {
    let log_severity = verbosity_to_level_filter(verbosity);

    // mute logs from other crates and those below the log_severity level
    let filter = filter::Targets::new().with_target(env!("CARGO_PKG_NAME"), log_severity);

    let plain_log = if log_format == LogType::Plain {
        Some(tracing_subscriber::fmt::layer())
    } else {
        None
    };

    let json_log = if log_format == LogType::Json {
        Some(tracing_subscriber::fmt::layer().json())
    } else {
        None
    };

    let tracing = if otel_config.tracing_enabled {
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(otel_config.otlp_endpoint)
                    .with_timeout(Duration::from_secs(OTLP_TIMEOUT_SECONDS)),
            )
            .with_trace_config(
                trace::config()
                    .with_sampler(Sampler::AlwaysOn)
                    .with_id_generator(RandomIdGenerator::default())
                    .with_resource(Resource::new(vec![KeyValue::new(
                        "service.name",
                        otel_config.service_name,
                    )])),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)?;

        Some(tracing_opentelemetry::layer().with_tracer(tracer))
    } else {
        None
    };

    let subscriber = Registry::default()
        .with(filter)
        .with(plain_log)
        .with(json_log)
        .with(tracing);

    Ok(subscriber)
}

pub fn verbosity_to_level_filter(severity: u8) -> LevelFilter {
    match severity {
        0 => LevelFilter::INFO,
        1 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    }
}

pub fn set_parent_from_event(target_span: &Span, event: &NormalizedEvent) {
    let propagator = TraceContextPropagator::new();
    let parent_context = propagator.extract(&event.carrier);
    target_span.set_parent(parent_context);
}

pub fn store_parent_into_event(parent_span: &Span, event: &mut NormalizedEvent) {
    let mut carrier = HashMap::new();
    let context = parent_span.context();
    let propagator = TraceContextPropagator::new();
    propagator.inject_context(&context, &mut carrier);
    event.carrier = carrier;
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_tracer() {
        let level = verbosity_to_level_filter(10);
        assert!(level == LevelFilter::TRACE);
        let level = verbosity_to_level_filter(0);
        assert!(level == LevelFilter::INFO);
        let level = verbosity_to_level_filter(1);
        assert!(level == LevelFilter::DEBUG);
        let mut config = OtelConfig {
            otlp_endpoint: "http://localhost:4317".to_string(),
            service_name: "test".to_string(),
            tracing_enabled: true,
            ..Default::default()
        };
        {
            let sub = setup(1, LogType::Plain, config.clone()).unwrap();
            let _g = tracing::subscriber::set_default(sub);
        }
        {
            // can't enable tracing layer twice
            config.tracing_enabled = false;
            let sub = setup(1, LogType::Json, config).unwrap();
            let _g = tracing::subscriber::set_default(sub);
        }
    }
}
