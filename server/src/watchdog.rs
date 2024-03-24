use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use metered::hdr_histogram::HdrHistogram;
use tokio::{
    sync::{broadcast, mpsc},
    time::interval,
};
use tracing::{info, warn};

pub mod eps;

use crate::{
    event::NormalizedEvent,
    filter::ManagerReport,
    tracer::{self, OtelConfig},
};

pub const REPORT_INTERVAL_IN_SECONDS: u64 = 10;
const RESET_EPS_EVERY_SECONDS: u64 = 60;
const UNIT_MULTIPLIER: f64 = 1000000.0; // nano to milli

#[derive(Default)]
pub struct Watchdog {}
pub struct WatchdogOpt {
    pub event_tx: broadcast::Sender<NormalizedEvent>,
    pub resptime_rx: mpsc::Receiver<f64>,
    pub report_rx: mpsc::Receiver<ManagerReport>,
    pub cancel_tx: broadcast::Sender<()>,
    pub report_interval: u64,
    pub ttl_directives: usize,
    pub max_eps: u32,
    pub otel_config: OtelConfig,
    pub eps: Arc<eps::Eps>,
    pub log_verbosity: u8,
    pub log_format: tracer::LogType,
    pub require_logging: bool,
}

impl Watchdog {
    pub async fn start(&mut self, opt: WatchdogOpt) -> Result<()> {
        let subscriber = tracer::setup(opt.log_verbosity, opt.log_format, opt.otel_config.clone())?;
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            if opt.require_logging {
                return Err(e.into());
            }
        }

        let mut report = interval(Duration::from_secs(opt.report_interval));
        let mut cancel_rx = opt.cancel_tx.subscribe();
        let mut resp_histo = HdrHistogram::with_bound(60 * 60 * 1000 * UNIT_MULTIPLIER as u64); // max 1 hour
        let max_proc_time_ms = 1000.0 / opt.max_eps as f64;
        let mut report_map = HashMap::<u64, (usize, usize, usize)>::new();
        let mut resptime_rx = opt.resptime_rx;
        let mut report_rx = opt.report_rx;

        let mut meter = crate::meter::Meter::new(opt.otel_config);

        if let Some(ref mut meter) = meter {
            for s in &["dsiem_eps", "dsiem_avg_proc_time_ms"] {
                meter.upsert_f64(s, None)?;
            }
            for s in &[
                "dsiem_queue_length",
                "dsiem_directives_total",
                "dsiem_directives_active",
                "dsiem_events",
                "dsiem_events_matched",
                "dsiem_backlogs",
                "dsiem_backlogs_timedout",
            ] {
                meter.upsert_u64(s, None)?;
            }
            meter.start()?;
        }

        let round = |x: f64, decimals: u32| -> f64 {
            let y = (10i64).pow(decimals) as f64;
            (x * y).round() / y
        };

        let mut eps_timer_start = Instant::now();

        loop {
            tokio::select! {
                biased;
                _ = cancel_rx.recv() => {
                  info!("cancel signal received, exiting watchdog thread");
                  break;
                }
                Some(v) = resptime_rx.recv() => {
                    resp_histo.record(v as u64);
                }
                Some(v) = report_rx.recv() => {
                    report_map.insert(
                    v.id,
                    (v.active_backlogs, v.timedout_backlogs, v.matched_events)
                    );
                }
                _ = report.tick() => {

                    let eps = round(opt.eps.metrics.count.throughput.histogram().mean(), 2);
                    let events_count = opt.eps.metrics.count.hit_count.get();
                    let queue_length = opt.event_tx.len();

                    let active_directives =
                        report_map.iter().filter(|&(_, (x, _, _))|*x > 0).count();
                    let (backlogs, timedout_backlogs, matched_events) =
                        report_map
                            .values()
                            .fold((0, 0, 0), |acc, x| (acc.0 + x.0, acc.1 + x.1, acc.2 + x.2));

                    // reset this if there's no processed events since last report
                    let avg_proc_time_ms = match matched_events {
                        0 => {
                            resp_histo.clear();
                            0.0
                        },
                        _ => resp_histo.mean()/UNIT_MULTIPLIER
                    };

                    if let Some(ref mut meter) = meter {
                        meter.upsert_f64("dsiem_eps", Some(eps))?;
                        meter.upsert_f64("dsiem_avg_proc_time_ms", Some(avg_proc_time_ms))?;
                        meter.upsert_u64("dsiem_queue_length", Some(queue_length as u64))?;
                        meter.upsert_u64("dsiem_directives_total", Some(opt.ttl_directives as u64))?;
                        meter.upsert_u64("dsiem_directives_active", Some(active_directives as u64))?;
                        meter.upsert_u64("dsiem_events", Some(events_count))?;
                        meter.upsert_u64("dsiem_events_matched", Some(matched_events as u64))?;
                        meter.upsert_u64("dsiem_backlogs", Some(backlogs as u64))?;
                        meter.upsert_u64("dsiem_backlogs_timedout", Some(timedout_backlogs as u64))?;
                    }

                    let rounded_avg_proc_time_ms = (avg_proc_time_ms * 1000.0).round() / 1000.0;

                    info!(
                        eps,
                        queue_length,
                        avg_proc_time_ms =  rounded_avg_proc_time_ms,
                        directives_ttl = opt.ttl_directives,
                        directives_active = active_directives,
                        events_rcvd = events_count,
                        events_matched = matched_events,
                        backlogs,
                        backlogs_timedout = timedout_backlogs,
                        "watchdog report"
                    );

                    if events_count != 0 {
                        eps_timer_start = Instant::now();
                    } else if eps_timer_start.elapsed().as_secs() >= RESET_EPS_EVERY_SECONDS && eps > 0.01 {
                        // this injects 1 event to wind down the histogram if there's no events
                        // for a period of RESET_EPS_EVERY_SECONDS.
                        opt.eps.count();
                        eps_timer_start = Instant::now();
                    }

                    // reset, this only counts received events since last report
                    opt.eps.metrics.count.hit_count.set(0);

                    if queue_length != 0 && avg_proc_time_ms > max_proc_time_ms {
                    warn!(
                        avg_proc_time_ms = rounded_avg_proc_time_ms,
                        "avg. processing time maybe too long to sustain the target {} event/sec (or {:.3} ms/event)",
                        opt.max_eps,
                        max_proc_time_ms
                    );
                    // reset so next it excludes any previous outliers
                    resp_histo.clear();
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use tokio::{task, time::sleep};
    use tracing::{Instrument, Span};
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[traced_test]
    async fn test_watchdog() {
        let (event_tx, _event_rx) = broadcast::channel::<NormalizedEvent>(5);
        let (resptime_tx, resptime_rx) = mpsc::channel::<f64>(1);
        let (report_tx, report_rx) = mpsc::channel::<ManagerReport>(1);
        let (cancel_tx, _) = broadcast::channel::<()>(5);
        let report_interval = 1;
        let max_eps = 1000;

        let eps = Arc::new(eps::Eps::default());

        let otel_config = OtelConfig { metrics_enabled: true, ..Default::default() };

        let opt = WatchdogOpt {
            event_tx: event_tx.clone(),
            resptime_rx,
            report_rx,
            cancel_tx: cancel_tx.clone(),
            report_interval,
            ttl_directives: 1,
            max_eps,
            otel_config,
            eps,
            log_verbosity: 0,
            log_format: tracer::LogType::Plain,
            require_logging: false,
        };

        let span = Span::current();
        task::spawn(async {
            let mut w = Watchdog::default();
            _ = w.start(opt).instrument(span).await;
        });

        let rpt = ManagerReport { id: 1, active_backlogs: 100, timedout_backlogs: 0, matched_events: 9001 };
        _ = report_tx.send(rpt).await;
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("backlogs=100"));

        _ = resptime_tx.send(100.0 * UNIT_MULTIPLIER).await;
        _ = resptime_tx.send(100.0 * UNIT_MULTIPLIER).await;
        _ = resptime_tx.send(25.0 * UNIT_MULTIPLIER).await;
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("avg_proc_time_ms=74") || logs_contain("avg_proc_time_ms=75"));

        sleep(Duration::from_millis(1000)).await;
        _ = resptime_tx.send(10000.0 * UNIT_MULTIPLIER).await;
        sleep(Duration::from_millis(1000)).await;

        // this should trigger a clear() on the histogram
        let _handle = task::spawn(async move {
            for _ in 0..10000 {
                event_tx.send(NormalizedEvent::default()).unwrap();
            }
        });
        sleep(Duration::from_millis(3000)).await;
        assert!(logs_contain("processing time maybe too long"));

        _ = resptime_tx.send(25.0 * UNIT_MULTIPLIER).await;
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("avg_proc_time_ms=24") || logs_contain("avg_proc_time_ms=25"));

        let rpt = ManagerReport { id: 1, active_backlogs: 100, timedout_backlogs: 0, matched_events: 0 };
        _ = report_tx.send(rpt).await;
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("avg_proc_time_ms=0.0"));

        cancel_tx.send(()).unwrap();
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("cancel signal received"));
    }
}
