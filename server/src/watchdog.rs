use std::{collections::HashMap, time::Duration};

use anyhow::Result;
use metered::{hdr_histogram::HdrHistogram, metered, Throughput};
use tokio::{
    sync::{broadcast, mpsc},
    time::interval,
};
use tracing::{info, warn};

use crate::{event::NormalizedEvent, manager::ManagerReport, tracer::OtelConfig};

pub const REPORT_INTERVAL_IN_SECONDS: u64 = 10;

#[derive(Default)]
pub struct Watchdog {
    metrics: Metrics,
}
pub struct WatchdogOpt {
    pub event_tx: broadcast::Sender<NormalizedEvent>,
    pub event_rx: broadcast::Receiver<NormalizedEvent>,
    pub resptime_rx: mpsc::Receiver<Duration>,
    pub report_rx: mpsc::Receiver<ManagerReport>,
    pub cancel_tx: broadcast::Sender<()>,
    pub report_interval: u64,
    pub max_eps: u32,
    pub otel_config: OtelConfig,
}

#[metered(registry = Metrics)]
impl Watchdog {
    pub async fn start(&mut self, opt: WatchdogOpt) -> Result<()> {
        let mut report = interval(Duration::from_secs(opt.report_interval));
        let mut cancel_rx = opt.cancel_tx.subscribe();
        let mut resp_histo = HdrHistogram::with_bound(60 * 60 * 1000); // max 1 hour
        let max_proc_time_ms = 1000.0 / opt.max_eps as f64;
        let mut report_map = HashMap::<u64, usize>::new();
        let mut resptime_rx = opt.resptime_rx;
        let mut report_rx = opt.report_rx;
        let mut event_rx = opt.event_rx;

        let mut meter = crate::meter::Meter::new(opt.otel_config);

        if let Some(ref mut meter) = meter {
            for s in &["dsiem_eps", "dsiem_avg_proc_time_ms"] {
                meter.upsert_f64(s, None)?;
            }
            for s in &[
                "dsiem_queue_length",
                "dsiem_ttl_directives",
                "dsiem_active_directives",
                "dsiem_backlogs",
            ] {
                meter.upsert_u64(s, None)?;
            }
            meter.start()?;
        }

        loop {
            tokio::select! {
                _ = cancel_rx.recv() => {
                  info!("cancel signal received, exiting watchdog thread");
                  break;
                }
                Some(v) = resptime_rx.recv() => {
                  if let Ok(n) = u64::try_from(v.as_millis()) {
                    resp_histo.record(n);
                  }
                }
                Some(v) = report_rx.recv() => {
                  report_map.insert(v.id, v.active_backlogs);
                }
                _ = report.tick() => {

                let eps = round(self.metrics.eps.throughput.histogram().mean(), 2);
                let queue_length = opt.event_tx.len();
                let avg_proc_time_ms = round(resp_histo.mean(), 3);
                let ttl_directives = report_map.len();
                let active_directives =  report_map.iter().filter(|&(_, v)| *v > 0).count();
                let backlogs = report_map.values().sum::<usize>();

                if let Some(ref mut meter) = meter {
                  meter.upsert_f64("dsiem_eps", Some(eps))?;
                  meter.upsert_f64("dsiem_avg_proc_time_ms", Some(avg_proc_time_ms))?;
                  meter.upsert_u64("dsiem_queue_length", Some(queue_length as u64))?;
                  meter.upsert_u64("dsiem_ttl_directives", Some(ttl_directives as u64))?;
                  meter.upsert_u64("dsiem_active_directives", Some(active_directives as u64))?;
                  meter.upsert_u64("dsiem_backlogs", Some(backlogs as u64))?;
                }

                info!(
                  eps,
                  queue_length,
                  avg_proc_time_ms,
                  ttl_directives,
                  active_directives,
                  backlogs,
                  "watchdog report"
                );

                if queue_length != 0 && avg_proc_time_ms > max_proc_time_ms {
                  warn!(avg_proc_time_ms, "avg. processing time maybe too long to sustain the target {} event/sec (or {} ms/event)", opt.max_eps, max_proc_time_ms );
                }
              }

              Ok(_) = event_rx.recv() => {
                self.eps()
              }
            }
        }
        Ok(())
    }

    #[measure([Throughput])]
    fn eps(&self) {}
}

fn round(x: f64, decimals: u32) -> f64 {
    let y = (10i64).pow(decimals) as f64;
    (x * y).round() / y
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::{task, time::sleep};
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_watchdog() {
        let (event_tx, event_rx) = broadcast::channel::<NormalizedEvent>(5);
        let (resptime_tx, resptime_rx) = mpsc::channel::<Duration>(1);
        let (report_tx, report_rx) = mpsc::channel::<ManagerReport>(1);
        let (cancel_tx, _) = broadcast::channel::<()>(5);
        let report_interval = 1;
        let max_eps = 1000;

        let opt = WatchdogOpt {
            event_tx: event_tx.clone(),
            event_rx,
            resptime_rx,
            report_rx,
            cancel_tx: cancel_tx.clone(),
            report_interval,
            max_eps,
            otel_config: OtelConfig::default(),
        };

        let _detached = task::spawn(async {
            let mut w = Watchdog::default();
            _ = w.start(opt).await;
        });
        _ = resptime_tx.send(Duration::from_millis(100)).await;
        _ = resptime_tx.send(Duration::from_millis(100)).await;
        _ = resptime_tx.send(Duration::from_millis(25)).await;
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("avg_proc_time_ms=75.0"));

        for _ in 0..100000 {
            let e = NormalizedEvent::default();
            _ = event_tx.send(e);
        }
        _ = resptime_tx.send(Duration::from_millis(10000)).await;
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("processing time maybe too long"));

        let rpt = ManagerReport {
            id: 1,
            active_backlogs: 100,
        };
        _ = report_tx.send(rpt).await;
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("avg_proc_time_ms=75.0"));
        cancel_tx.send(()).unwrap();
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("cancel signal received"));
    }
}
