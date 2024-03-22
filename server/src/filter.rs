use crate::{
    allocator::ThreadAllocation,
    backlog::loader::LazyLoaderConfig,
    event::NormalizedEvent,
    rule::{self, DirectiveRule},
    tracer,
};
use mini_moka::sync::Cache;
use std::{sync::Arc, thread, vec};
use tracing::{debug, error, info, info_span, trace, warn, Span};

use anyhow::Result;
use tokio::sync::{
    broadcast::{self, error::RecvError},
    mpsc, oneshot, Notify,
};

pub struct FilterOpt {
    pub lazy_loader: Option<LazyLoaderConfig>,
    pub thread_allocation: ThreadAllocation,
    pub notifier: Arc<Notify>,
    pub cancel_tx: broadcast::Sender<()>,
}

// re-export
pub use crate::backlog::manager::ManagerReport;

mod cache;

#[derive(Clone)]
pub struct FilterTarget {
    pub id: u64,
    pub tx: mpsc::Sender<NormalizedEvent>,
    pub sid_pairs: Vec<rule::SIDPair>,
    pub taxo_pairs: Vec<rule::TaxoPair>,
    pub contains_pluginrule: bool,
    pub contains_taxorule: bool,
}

impl FilterTarget {
    pub fn insert(
        id: u64,
        rules: &[DirectiveRule],
        event_tx: mpsc::Sender<NormalizedEvent>,
        targets: &mut Vec<FilterTarget>,
    ) {
        let (mut sid_pairs, mut taxo_pairs) = rule::get_quick_check_pairs(rules);
        let contains_pluginrule = !sid_pairs.is_empty();
        let contains_taxorule = !taxo_pairs.is_empty();
        sid_pairs.shrink_to_fit();
        taxo_pairs.shrink_to_fit();
        targets.push(FilterTarget {
            id,
            tx: event_tx,
            sid_pairs,
            taxo_pairs,
            contains_pluginrule,
            contains_taxorule,
        });
    }
}

pub type OnDemandIDMessage = (u64, oneshot::Sender<()>);

pub struct Filter {
    option: FilterOpt,
}

impl Filter {
    pub fn new(option: FilterOpt) -> Self {
        Self { option }
    }

    pub fn start(
        &self,
        publisher: broadcast::Sender<NormalizedEvent>,
        targets: Vec<FilterTarget>,
        id_tx: Option<mpsc::Sender<OnDemandIDMessage>>,
    ) -> Result<()> {
        let active_ids = match &self.option.lazy_loader {
            Some(l) => l.cache.clone(),
            None => Cache::builder().max_capacity(0).build(), // fix this
        };

        let preload_directives = self.option.lazy_loader.is_none();

        let dir_len = targets.len();
        let chunk_size = dir_len / self.option.thread_allocation.filter_threads;

        let r = targets.chunks(chunk_size).collect::<Vec<_>>();
        let mut chunks = vec![];
        for c in r {
            chunks.push(c.to_owned());
        }

        let mut handles = vec![];

        for (idx, c) in chunks.into_iter().enumerate() {
            let rx = publisher.subscribe();
            let id_tx = id_tx.clone();
            let active_ids = active_ids.clone();
            let span = Span::current();

            let handle = thread::spawn(move || {
                Filter::event_handler(idx, rx, id_tx, preload_directives, active_ids, c, span)
            });
            handles.push(handle);
        }

        self.option.notifier.notify_one();

        // drop publisher to signal all filter threads to exit
        drop(publisher);
        for h in handles {
            _ = h.join();
        }

        info!("manager exiting");

        // tell all others to exit if they havent
        _ = self.option.cancel_tx.send(());

        Ok(())
    }

    fn event_handler(
        id: usize,
        mut rx: broadcast::Receiver<NormalizedEvent>,
        id_tx: Option<mpsc::Sender<OnDemandIDMessage>>,
        preload_directives: bool,
        active_ids: Cache<u64, ()>,
        c: Vec<FilterTarget>,
        span: Span,
    ) {
        let matched_with_event = |p: &FilterTarget, event: &NormalizedEvent| -> bool {
            (p.contains_pluginrule && rule::quick_check_plugin_rule(&p.sid_pairs, event))
                || (p.contains_taxorule && rule::quick_check_taxo_rule(&p.taxo_pairs, event))
        };

        let _h = span.entered();
        let filter_span = info_span!("filter thread", thread.id = id);
        let _h = filter_span.enter();

        // thread local cache for this specific chunk of directives
        let sid_cache = cache::create_sid_cache(&c);
        let sid_cache_enabled = !sid_cache.is_empty();
        let taxo_cache = cache::create_taxo_cache(&c);
        let taxo_cache_enabled = !taxo_cache.is_empty();

        loop {
            let mut event = match rx.blocking_recv() {
                Ok(event) => event,
                Err(RecvError::Lagged(n)) => {
                    warn!("filtering lagged and skipped {} events", n);
                    continue;
                }
                Err(RecvError::Closed) => {
                    info!("filtering event receiver closed");
                    break;
                }
            };

            // heuristic to filter out events that are not worth processing
            let mut found = false;
            if event.plugin_id != 0
                && event.plugin_sid != 0
                && sid_cache_enabled
                && sid_cache
                    .get(&(event.plugin_id, event.plugin_sid))
                    .is_some()
            {
                found = true;
            }

            // check this only when there's no plugin rule match
            if !found
                && !event.product.is_empty()
                && !event.category.is_empty()
                && taxo_cache_enabled
                && taxo_cache
                    .get(&(event.product.clone(), event.category.clone()))
                    .is_some()
            {
                found = true;
            }

            if !found {
                trace!(event.id, "event doesn't match any rule, skipping");
                continue;
            }

            // here we just need to find the directive(s) that match the event
            let matched_dirs: Vec<&FilterTarget> =
                c.iter().filter(|p| matched_with_event(p, &event)).collect();
            debug!(
                event.id,
                "event matched rules in {} directive(s)",
                matched_dirs.len()
            );

            let distrib_span = info_span!("event distribution", event.id);
            tracer::set_parent_from_event(&distrib_span, &event);
            let _ = distrib_span.enter();
            tracer::store_parent_into_event(&distrib_span, &mut event);

            matched_dirs.iter().for_each(|d| {

                // if preload directive is false, send the directive id to the spawner
                // do this only when the directive isn't already in the active_ids
                if !preload_directives && !active_ids.contains_key(&d.id) {
                    if let Some(id_tx) = &id_tx {
                        let id_tx = id_tx.clone();
                        debug!(directive.id = d.id, "sending directive ID to spawner");
                        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

                        if let Err(e) = id_tx.blocking_send((d.id, tx)) {
                            error!(
                                directive.id = d.id,
                                event.id, "skipping, filter can't send id to spawner: {}", e
                            );
                            return;
                        }
                        // waiting for the spawner to acknowledge backlog manager creation
                        debug!(directive.id = d.id, "waiting confirmation from spawner");
                        if let Err (e) = rx.blocking_recv() {
                            // failure could mean there's already an existing backlog manager for this directive
                            // so we should just try to send the event anyway
                            warn!(
                                directive.id = d.id,
                                event.id, "spawner failed to confirm backlog manager creation: {}, will try to send the event anyway", e
                            );
                        }
                    }
                }

                debug!(
                    directive.id = d.id,
                    event.id, "sending event to backlog manager"
                );
                if d.tx.try_send(event.clone()).is_err() {
                    warn!(
                        directive.id = d.id,
                        event.id, "backlog manager lagged or no longer active, dropping event"
                    );
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread, time::Duration};

    use crate::{
        allocator::ThreadAllocation,
        asset::NetworkAssets,
        backlog::{self, manager::QueueMode},
        directive::{self, Directive},
        event::NormalizedEvent,
        filter::{self, Filter, FilterOpt, ManagerReport},
        intel,
        log_writer::{LogWriter, LogWriterMessage},
        parser,
        parser::ParserOpt,
        vuln,
    };

    use backlog::loader::LazyLoaderConfig;
    use tokio::{
        runtime::Handle,
        sync::{
            broadcast::{self, Sender},
            mpsc, Notify,
        },
        task,
        time::sleep,
    };
    use tracing::{debug, Instrument, Span};
    use tracing_test::traced_test;

    fn get_parser_opt(
        c: Sender<()>,
        r: mpsc::Sender<ManagerReport>,
        reload_backlogs: bool,
        lazy_loader: Option<LazyLoaderConfig>,
        log_tx: crossbeam_channel::Sender<LogWriterMessage>,
    ) -> ParserOpt {
        let (backpressure_tx, _) = mpsc::channel::<()>(8);
        let (resptime_tx, _) = mpsc::channel::<f64>(128);

        let assets = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let intels =
            Arc::new(intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap());
        let vulns = Arc::new(vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap());
        let load_param = backlog::manager::OpLoadParameter {
            max_wait: Duration::from_millis(100),
            limit_cap: 1000,
            queue_mode: QueueMode::Bounded,
        };
        ParserOpt {
            test_env: true,
            lazy_loader,
            reload_backlogs,
            assets,
            intels,
            vulns,
            intel_private_ip: false,
            max_delay: 0,
            min_alarm_lifetime: 0,
            backpressure_tx,
            cancel_tx: c,
            resptime_tx,
            default_status: "Open".to_string(),
            default_tag: "Identified Threat".to_string(),
            med_risk_min: 3,
            med_risk_max: 6,
            report_tx: r,
            load_param,
            log_tx,
        }
    }

    fn get_filter_opt(cancel_tx: broadcast::Sender<()>) -> FilterOpt {
        let notifier = Notify::new();
        FilterOpt {
            lazy_loader: None,
            thread_allocation: ThreadAllocation {
                filter_threads: 1,
                tokio_threads: 1,
            },
            notifier: Arc::new(notifier),
            cancel_tx,
        }
    }
    async fn run_manager(
        directives: Vec<Directive>,
        event_tx: broadcast::Sender<NormalizedEvent>,
        cancel_tx: broadcast::Sender<()>,
        report_tx: mpsc::Sender<ManagerReport>,
        reload_backlogs: bool,
        lazy_loader: Option<LazyLoaderConfig>,
    ) -> task::JoinHandle<()> {
        let opt = get_filter_opt(cancel_tx.clone());
        let span = Span::current();
        let tx_clone = event_tx.clone();

        let mut log_writer = LogWriter::new(true).unwrap();
        let log_tx = log_writer.sender.clone();

        let (targets, loader, id_rx) = parser::targets_and_loader_from_directives(
            &directives,
            true,
            &get_parser_opt(
                cancel_tx.clone(),
                report_tx.clone(),
                reload_backlogs,
                lazy_loader,
                log_tx,
            ),
        );
        task::spawn_blocking(move || {
            let _h = span.entered();

            debug!("running log writer");
            let _ = thread::spawn(move || log_writer.listener());

            debug!("starting manager loader");
            let _ = loader.run(Handle::current());

            debug!("starting filter");
            let f = Filter::new(opt);
            _ = f.start(tx_clone, targets, id_rx);
            debug!("shouldnt exit")
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    #[traced_test]
    async fn test_filter_and_loader_preload_dirs() {
        let directives = directive::load_directives(
            true,
            Some(vec!["directives".to_string(), "directive5".to_string()]),
        )
        .unwrap();
        let (cancel_tx, _) = broadcast::channel::<()>(1);
        let (report_tx, mut report_rx) = mpsc::channel::<filter::ManagerReport>(directives.len());

        let span = Span::current();
        let _report_receiver = task::spawn(
            async move {
                // test comparing report
                let rpt1 = ManagerReport {
                    id: 1,
                    active_backlogs: 1,
                    timedout_backlogs: 0,
                    matched_events: 0,
                };
                let mut rpt2 = ManagerReport {
                    id: 1,
                    active_backlogs: 1,
                    timedout_backlogs: 0,
                    matched_events: 0,
                };
                assert!(rpt1 == rpt2);
                rpt2.active_backlogs = 2;
                assert!(rpt1 != rpt2);
                while report_rx.recv().await.is_some() {
                    debug!("report received");
                }
            }
            .instrument(span),
        );

        let (event_tx, _) = broadcast::channel(1024);

        let manager_handle = run_manager(
            directives.clone(),
            event_tx.clone(),
            cancel_tx.clone(),
            report_tx.clone(),
            false,
            None,
        )
        .await;

        let mut evt = NormalizedEvent {
            id: "0a".to_string(),
            plugin_id: 31337,
            plugin_sid: 2,
            custom_label1: "label".to_string(),
            custom_data1: "data".to_string(),
            ..Default::default()
        };

        sleep(Duration::from_millis(3000)).await;

        // assert that the backlog manager is listening for events
        assert!(logs_contain("listening for event directive.id=1"));

        // unmatched event
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(2000)).await;

        assert!(logs_contain("event doesn't match any rule"));

        // matched event but not on the first rule
        evt.id = "0b".to_string();
        evt.plugin_id = 1337;
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("event doesn't match first rule"));

        // matched event 1
        evt.plugin_sid = 1;
        evt.id = "1".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("creating new backlog"));

        // matched event 2
        evt.id = "2".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("event sent downstream"));
        assert!(logs_contain(
            "found existing backlog that consumes the event"
        ));

        // matched event 3 to 5
        evt.id = "3".to_string();
        event_tx.send(evt.clone()).unwrap();
        evt.id = "4".to_string();
        event_tx.send(evt.clone()).unwrap();
        evt.id = "5".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(3000)).await;
        assert!(logs_contain("cleaning deleted backlog"));

        // report tick
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("report received"));

        // create another backlog
        evt.plugin_sid = 1;
        evt.id = "6".to_string();
        evt.timestamp = chrono::Utc::now();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("creating new backlog"));

        _ = cancel_tx.send(());
        sleep(Duration::from_millis(4000)).await;
        drop(event_tx);
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("manager exiting"));

        _ = manager_handle.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    #[traced_test]
    async fn test_filter_and_loader_no_preload_dirs() {
        let directives = directive::load_directives(
            true,
            Some(vec!["directives".to_string(), "directive5".to_string()]),
        )
        .unwrap();
        let (cancel_tx, _) = broadcast::channel::<()>(1);
        let (report_tx, mut report_rx) = mpsc::channel::<filter::ManagerReport>(directives.len());

        let span = Span::current();
        let _report_receiver = task::spawn(
            async move {
                while report_rx.recv().await.is_some() {
                    debug!("report received");
                }
            }
            .instrument(span),
        );

        let (event_tx, _) = broadcast::channel(1024);

        let l = LazyLoaderConfig::new(directives.len(), 100)
            .with_dirs_idle_timeout_checker_interval_sec(10);

        // this function should be the only location where reload_backlogs is true, otherwise we risk having multiple tests trying to save/load/delete from disk

        let manager_handle = run_manager(
            directives.clone(),
            event_tx.clone(),
            cancel_tx.clone(),
            report_tx.clone(),
            true,
            Some(l.clone()),
        )
        .await;

        let mut evt = NormalizedEvent {
            id: "0a".to_string(),
            plugin_id: 31337,
            plugin_sid: 2,
            custom_label1: "label".to_string(),
            custom_data1: "data".to_string(),
            ..Default::default()
        };

        sleep(Duration::from_millis(1000)).await;

        // unmatched event
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(2000)).await;

        assert!(logs_contain("event doesn't match any rule"));

        // matched event but not on the first rule
        evt.id = "0b".to_string();
        evt.plugin_id = 1337;
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("event doesn't match first rule"));

        // matched event 1
        evt.plugin_sid = 1;
        evt.id = "1".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;

        // assert that the backlog manager is listening for events
        assert!(logs_contain("listening for event directive.id=1"));

        assert!(logs_contain("creating new backlog"));

        // matched event 2
        evt.id = "2".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("event sent downstream"));
        assert!(logs_contain(
            "found existing backlog that consumes the event"
        ));

        // matched event 3 to 5
        evt.id = "3".to_string();
        event_tx.send(evt.clone()).unwrap();
        evt.id = "4".to_string();
        event_tx.send(evt.clone()).unwrap();
        evt.id = "5".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(3000)).await;
        assert!(logs_contain("cleaning deleted backlog"));

        // report tick
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("report received"));

        // create another backlog
        evt.plugin_sid = 1;
        evt.id = "6".to_string();
        evt.timestamp = chrono::Utc::now();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("creating new backlog"));

        // cancel signal, should also trigger saving to disk

        _ = cancel_tx.send(());
        sleep(Duration::from_millis(1000)).await;
        logs_contain("backlogs saved");

        drop(event_tx);
        sleep(Duration::from_millis(5000)).await;

        assert!(logs_contain("manager exiting"));

        _ = manager_handle.await;

        // restart to simulate reloading saved backlogs

        let (event_tx, _) = broadcast::channel::<NormalizedEvent>(1);
        let manager_handle = run_manager(
            directives.clone(),
            event_tx.clone(),
            cancel_tx.clone(),
            report_tx.clone(),
            true,
            Some(l),
        )
        .await;

        sleep(Duration::from_millis(2000)).await;

        assert!(logs_contain(
            "found 1 saved backlogs, instructing spawner to activate"
        ));
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain(
            "spawner received directive ID from filter directive.id=1"
        ));

        _ = cancel_tx.send(());
        drop(event_tx);
        sleep(Duration::from_millis(3000)).await;
        _ = manager_handle.await;

        /* uncomment this block if directive rules are applied to backlog, which for now isn't

        // get to stage 4
        for id in 7..10 {
            evt.id = id.to_string();
            evt.timestamp = chrono::Utc::now();
            event_tx.send(evt.clone()).unwrap();
            sleep(Duration::from_millis(500)).await;
        }
        _ = cancel_tx.send(());
        sleep(Duration::from_millis(4000)).await;
        assert!(logs_contain("1 backlogs saved"));

        // try reloading with updated directive that has reduced number of stages
        let updated: Vec<Directive> = directives
            .clone()
            .into_iter()
            .map(|mut d| {
                d.rules.retain(|x| x.stage < 4);
                d
            })
            .collect();
        _ = run_manager(updated);
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("lower than backlog's current stage"));

        */
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    #[traced_test]
    async fn test_filter_and_loader_directives_timeout() {
        let directives = directive::load_directives(
            true,
            Some(vec!["directives".to_string(), "directive5".to_string()]),
        )
        .unwrap();
        let (cancel_tx, _) = broadcast::channel::<()>(1);
        let (report_tx, mut report_rx) = mpsc::channel::<filter::ManagerReport>(directives.len());

        let span = Span::current();
        let _report_receiver = task::spawn(
            async move {
                while report_rx.recv().await.is_some() {
                    debug!("report received");
                }
            }
            .instrument(span),
        );

        let (event_tx, _) = broadcast::channel(1024);

        let loader = LazyLoaderConfig::new(directives.len(), 3)
            .with_dirs_idle_timeout_checker_interval_sec(1);

        let manager_handle = run_manager(
            directives.clone(),
            event_tx.clone(),
            cancel_tx.clone(),
            report_tx.clone(),
            false,
            Some(loader),
        )
        .await;

        let mut evt = NormalizedEvent {
            id: "0a".to_string(),
            plugin_id: 31337,
            plugin_sid: 2,
            custom_label1: "label".to_string(),
            custom_data1: "data".to_string(),
            ..Default::default()
        };

        sleep(Duration::from_millis(1000)).await;
        // matched event 1
        evt.plugin_sid = 1;
        evt.plugin_id = 1337;
        evt.id = "1".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;

        // assert that the backlog manager is listening for events
        assert!(logs_contain("listening for event directive.id=1"));

        assert!(logs_contain("creating new backlog"));

        // should be logged every second until backlog expires
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("backlogs is not empty resetting idle timeout"));

        // backlog should've expired, also the idle timeout of 3 secs after that
        sleep(Duration::from_secs(15)).await;
        assert!(logs_contain(
            "idle timeout reached, exiting backlog manager"
        ));

        // sending another event should instantiate a new backlog manager
        evt.id = "10".to_string();
        event_tx.send(evt).unwrap();
        sleep(Duration::from_millis(5000)).await;

        assert!(logs_contain(
            "backlog::manager: received event directive.id=1 event.id=\"10\""
        ));

        // teardown
        _ = cancel_tx.send(());
        drop(event_tx);
        _ = manager_handle.await;
    }
}
