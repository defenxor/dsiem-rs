use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::Result;
use opentelemetry::{
    global,
    metrics::{Meter as OtelMeter, MeterProvider},
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::{
        reader::{DefaultAggregationSelector, DefaultTemporalitySelector},
        PeriodicReader, SdkMeterProvider,
    },
    runtime, Resource,
};

use crate::{
    tracer::{OtelConfig, OTLP_TIMEOUT_SECONDS},
    watchdog::REPORT_INTERVAL_IN_SECONDS,
};

fn meter_provider(config: OtelConfig) -> Result<SdkMeterProvider> {
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(config.otlp_endpoint)
        .with_timeout(Duration::from_secs(OTLP_TIMEOUT_SECONDS))
        .build_metrics_exporter(
            Box::new(DefaultAggregationSelector::new()),
            Box::new(DefaultTemporalitySelector::new()),
        )?;
    let reader = PeriodicReader::builder(exporter, runtime::TokioCurrentThread)
        .with_interval(Duration::from_secs(REPORT_INTERVAL_IN_SECONDS))
        .build();
    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(Resource::new(vec![KeyValue::new("service.name", config.service_name)]))
        .build();
    Ok(provider)
}

fn global_meter(config: OtelConfig) -> Result<OtelMeter> {
    let provider = meter_provider(config.clone())?;
    global::set_meter_provider(provider);
    let provider = global::meter_provider();
    Ok(provider.meter(config.service_name))
}

pub struct Meter {
    meter: OtelMeter,
    gauges_f64: Arc<RwLock<HashMap<String, f64>>>,
    gauges_u64: Arc<RwLock<HashMap<String, u64>>>,
}

impl Meter {
    pub fn new(config: OtelConfig) -> Option<Self> {
        if !config.metrics_enabled {
            return None;
        }
        match global_meter(config) {
            Ok(meter) => Some(Self {
                meter,
                gauges_u64: Arc::new(RwLock::new(HashMap::new())),
                gauges_f64: Arc::new(RwLock::new(HashMap::new())),
            }),
            Err(_) => None,
        }
    }

    pub fn upsert_f64(&mut self, name: &str, value: Option<f64>) -> Result<()> {
        let mut w = self.gauges_f64.write().map_err(|_| anyhow::anyhow!("Error adding gauge"))?;
        w.insert(name.to_owned(), value.unwrap_or(0.0));
        Ok(())
    }
    pub fn upsert_u64(&mut self, name: &str, value: Option<u64>) -> Result<()> {
        let mut w = self.gauges_u64.write().map_err(|_| anyhow::anyhow!("Error adding gauge"))?;
        w.insert(name.to_owned(), value.unwrap_or(0));
        Ok(())
    }
    pub fn start(&mut self) -> Result<()> {
        let g = self.gauges_f64.read().map_err(|_| anyhow::anyhow!("Error reading gauges"))?;
        for (name, _) in g.clone().into_iter() {
            let gauge = self.meter.f64_observable_gauge(name.clone()).init();
            let lock = Arc::clone(&self.gauges_f64);
            self.meter.register_callback(&[gauge.as_any()], move |observer| {
                if let Ok(r) = lock.read() {
                    for (k, v) in r.iter() {
                        if *k == name {
                            // v will have been updated by watchdog by the time this is called
                            observer.observe_f64(&gauge, *v, &[]);
                        }
                    }
                };
            })?;
        }
        let g = self.gauges_u64.read().map_err(|_| anyhow::anyhow!("Error reading gauges"))?;
        for (name, _) in g.clone().into_iter() {
            let gauge = self.meter.u64_observable_gauge(name.clone()).init();
            let lock = Arc::clone(&self.gauges_u64);
            self.meter.register_callback(&[gauge.as_any()], move |observer| {
                if let Ok(r) = lock.read() {
                    for (k, v) in r.iter() {
                        if *k == name {
                            observer.observe_u64(&gauge, *v, &[]);
                        }
                    }
                };
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use tokio::time::sleep;

    use super::*;

    #[tokio::test]
    async fn test_meter() {
        let mut config = OtelConfig {
            otlp_endpoint: "bar".to_string(),
            service_name: "test".to_string(),
            tracing_enabled: false,
            metrics_enabled: false,
        };
        let m = Meter::new(config.clone());
        assert!(m.is_none());

        config.metrics_enabled = true;
        let m = Meter::new(config.clone());
        assert!(m.is_none());

        config.otlp_endpoint = "http://localhost:4317".to_string();

        let mut meter = Meter::new(config).unwrap();
        meter.upsert_f64("counter_f64", None).unwrap();
        meter.upsert_u64("counter_u64", None).unwrap();
        let res = meter.start();
        assert!(res.is_ok());
        meter.upsert_u64("counter_u64", Some(9002)).unwrap();
        meter.upsert_f64("counter_f64", Some(9001.0)).unwrap();

        sleep(Duration::from_secs(1)).await;
        let v = *meter.gauges_f64.read().unwrap().get("counter_f64").unwrap();
        assert_eq!(v, 9001.0);
        let v = *meter.gauges_u64.read().unwrap().get("counter_u64").unwrap();
        assert_eq!(v, 9002);
    }
}
