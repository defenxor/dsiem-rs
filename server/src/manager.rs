use crate::{
    asset::NetworkAssets,
    backlog::{self, Backlog, BacklogState},
    directive::Directive,
    event::NormalizedEvent,
    intel::IntelPlugin,
    log_writer::{LogWriter, LogWriterMessage},
    rule, tracer, utils,
    vuln::VulnPlugin,
};
use std::{fs::create_dir_all, sync::Arc, time::Duration, vec};
use tracing::{debug, error, info, info_span, trace, warn};

use anyhow::{anyhow, Result};
use tokio::{
    fs::{self, read_to_string, OpenOptions},
    io::{self, AsyncWriteExt},
    sync::{
        broadcast::{self, error::RecvError},
        mpsc, RwLock,
    },
    task::{self, JoinSet},
    time::{interval, sleep, timeout},
};

pub const UNBOUNDED_QUEUE_SIZE: usize = 1_000_000;
const DEADLOCK_TIMEOUT_IN_SECONDS: u64 = 10;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct ManagerReport {
    pub id: u64,
    pub active_backlogs: usize,
    pub timedout_backlogs: usize,
}

#[derive(Clone)]
pub struct ManagerOpt {
    pub test_env: bool,
    pub reload_backlogs: bool,
    pub directives: Vec<Directive>,
    pub assets: Arc<NetworkAssets>,
    pub intels: Arc<IntelPlugin>,
    pub vulns: Arc<VulnPlugin>,
    pub intel_private_ip: bool,
    pub max_delay: i64,
    pub min_alarm_lifetime: i64,
    pub backpressure_tx: mpsc::Sender<()>,
    pub cancel_tx: broadcast::Sender<()>,
    pub resptime_tx: mpsc::Sender<f64>,
    pub publisher: broadcast::Sender<NormalizedEvent>,
    pub default_status: String,
    pub default_tag: String,
    pub med_risk_min: u8,
    pub med_risk_max: u8,
    pub report_tx: mpsc::Sender<ManagerReport>,
    pub max_eps: u32,
    pub max_queue: usize,
}
pub struct Manager {
    option: ManagerOpt,
}

impl Manager {
    pub fn new(option: ManagerOpt) -> Result<Manager> {
        let m = Manager { option };
        Ok(m)
    }

    pub async fn load(test_env: bool, directive_id: u64) -> Result<Vec<Backlog>> {
        let backlog_dir = utils::log_dir(test_env)?.join("backlogs");
        let filename = backlog_dir.join(directive_id.to_string() + ".json");
        debug!(
            directive.id = directive_id,
            "loading {} (if it exist)",
            filename.to_string_lossy()
        );
        let s = read_to_string(filename.clone()).await?;
        // always remove the file if it exist, there could be content error in it
        _ = fs::remove_file(filename).await;
        let backlogs: Vec<Backlog> = serde_json::from_str(&s)?;
        Ok(backlogs)
    }

    pub async fn save(test_env: bool, directive_id: u64, source: Vec<Arc<Backlog>>) -> Result<()> {
        let backlog_dir = utils::log_dir(test_env)?.join("backlogs");
        create_dir_all(&backlog_dir)?;
        let filename = directive_id.to_string() + ".json";
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(backlog_dir.join(filename))
            .await?;

        let mut backlogs = vec![];
        for b in source.into_iter() {
            let saveable = Backlog::saveable_version(b).await;

            // if extra sanity check for occurrence & stage are needed, they should be done here
            // currently such tests are only during loading in Backlog::runable_version()

            backlogs.push(saveable);
        }

        let s = serde_json::to_string_pretty(&backlogs)? + "\n";
        file.write_all(s.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }

    pub async fn start(self, report_interval: u64) -> Result<()> {
        // use this for all directive managers
        let mut log_writer = LogWriter::new(self.option.test_env).await?;
        let log_tx = log_writer.sender.clone();
        let cancel_tx = self.option.cancel_tx.clone();
        task::spawn(async move { log_writer.listener(cancel_tx).await });

        let load_param = match self.option.max_queue {
            UNBOUNDED_QUEUE_SIZE => OpLoadParameter {
                limit_cap: UNBOUNDED_QUEUE_SIZE,
                max_wait: Duration::from_secs(DEADLOCK_TIMEOUT_IN_SECONDS),
                queue_mode: QueueMode::Unbounded,
            },
            _ => OpLoadParameter {
                limit_cap: self.option.max_queue * 9 / 10, // 90% of max_queue
                max_wait: Duration::from_millis((1000 / self.option.max_eps).into()),
                queue_mode: QueueMode::Bounded,
            },
        };

        info!("backlog manager started with max single event processing time: {} ms, and queue limit of {} events", load_param.max_wait.as_millis(), load_param.limit_cap);

        let mut set = JoinSet::new();
        let mut option = self.option.clone();
        option.directives = vec![];

        for directive in self.option.directives {
            let mut dir_manager =
                DirectiveManager::new(&option, &load_param, &directive, &log_tx, &report_interval); // Remove reference
            set.spawn(async move { dir_manager.start().await });
        }

        while set.join_next().await.is_some() {}
        info!("backlog manager exiting");
        Ok(())
    }
}

#[derive(Clone, PartialEq)]
enum QueueMode {
    Unbounded,
    Bounded,
}

#[derive(Clone)]
struct OpLoadParameter {
    limit_cap: usize,
    max_wait: Duration,
    queue_mode: QueueMode,
}

struct DirectiveManager {
    option: ManagerOpt,
    load_param: OpLoadParameter,
    directive: Directive,
    log_tx: mpsc::Sender<LogWriterMessage>,
    report_interval: u64,
    backlogs: RwLock<Vec<Arc<Backlog>>>,
    downstream_tx: broadcast::Sender<NormalizedEvent>,
    delete_tx: Option<mpsc::Sender<()>>,
}

impl DirectiveManager {
    fn new(
        option: &ManagerOpt,
        load_param: &OpLoadParameter,
        directive: &Directive,
        log_tx: &mpsc::Sender<LogWriterMessage>,
        report_interval: &u64,
    ) -> DirectiveManager {
        let (downstream_tx, _) = broadcast::channel(1024);
        let load_param = load_param.clone();
        let mut option = option.clone();
        option.directives = vec![];
        let log_tx = log_tx.clone();
        let directive = directive.clone();
        DirectiveManager {
            option,
            load_param,
            downstream_tx,
            backlogs: RwLock::new(vec![]),
            delete_tx: None,
            log_tx,
            directive,
            report_interval: *report_interval,
        }
    }

    async fn start_backlog(&self, evt: Option<NormalizedEvent>, backlog: Arc<Backlog>) {
        let rx = self.downstream_tx.subscribe();
        let max_delay = self.option.max_delay;
        let resptime_tx = self.option.resptime_tx.clone();
        let dir_id = self.directive.id;
        task::spawn(async move {
            info!(directive.id = dir_id, backlog.id, "starting backlog");
            if let Err(e) = backlog.start(rx, evt, resptime_tx, max_delay).await {
                error!(
                    directive.id = dir_id,
                    backlog.id, "backlog exited with an error: {}", e
                )
            }
        });
    }

    async fn reload_backlogs(&self) -> Result<()> {
        let mut backlogs = self.backlogs.write().await;
        let res = Manager::load(false, self.directive.id).await;
        match res {
            Err(e) => {
                for cause in e.chain() {
                    if let Some(e) = cause.downcast_ref::<io::Error>() {
                        if e.kind() != io::ErrorKind::NotFound {
                            info!(
                                directive.id = self.directive.id,
                                "cannot load backlogs: {:?}", e
                            );
                        }
                    }
                }
            }
            Ok(load_result) => {
                if !load_result.is_empty() {
                    info!(directive.id = self.directive.id, "reloading old backlog");
                }
                for b in load_result.into_iter() {
                    // perform all steps in backlog::new here
                    let id = &b.id.clone();
                    let opt = self.get_backlog_opt()?;
                    let res = Backlog::runnable_version(opt, b).await;
                    match res {
                        Err(e) => {
                            error!(
                                directive.id = self.directive.id,
                                backlog.id = id,
                                "cannot recreate backlog: {}",
                                e
                            );
                        }
                        Ok(b) => {
                            let arced = Arc::new(b);
                            let clone = Arc::clone(&arced);
                            backlogs.push(arced);
                            let _detached = self.start_backlog(None, clone).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn get_backlog_opt(&self) -> Result<backlog::BacklogOpt> {
        if let Some(tx) = self.delete_tx.clone() {
            return Ok(backlog::BacklogOpt {
                asset: self.option.assets.clone(),
                bp_tx: self.option.backpressure_tx.clone(),
                delete_tx: tx.clone(),
                log_tx: self.log_tx.clone(),
                intels: self.option.intels.clone(),
                vulns: self.option.vulns.clone(),
                min_alarm_lifetime: self.option.min_alarm_lifetime,
                default_status: self.option.default_status.clone(),
                default_tag: self.option.default_tag.clone(),
                med_risk_min: self.option.med_risk_min,
                med_risk_max: self.option.med_risk_max,
                intel_private_ip: self.option.intel_private_ip,
                directive: &self.directive,
                event: None,
            });
        }
        Err(anyhow!("delete_tx is not set"))
    }

    async fn start(&mut self) -> Result<()> {
        let (sid_pairs, taxo_pairs) = rule::get_quick_check_pairs(&self.directive.rules);
        let contains_pluginrule = !sid_pairs.is_empty();
        let contains_taxorule = !taxo_pairs.is_empty();

        let mut upstream = self.option.publisher.subscribe();
        let mut cancel_rx = self.option.cancel_tx.subscribe();
        let downstream_tx = self.downstream_tx.clone();
        let (delete_tx, mut delete_rx) = mpsc::channel::<()>(128);

        self.delete_tx = Some(delete_tx);

        let report_sender = self.option.report_tx.clone();
        let mut report = interval(Duration::from_secs(self.report_interval));

        let mut mgr_report = ManagerReport {
            id: self.directive.id,
            active_backlogs: 0,
            timedout_backlogs: 0,
        };

        let clean_deleted = || async {
            let mut backlogs = self.backlogs.write().await;
            debug!(
                directive.id = self.directive.id,
                "cleaning deleted backlog if any"
            );
            backlogs.retain(|x| {
                let s = x.state.read();
                *s == BacklogState::Created || *s == BacklogState::Running
            });
        };

        if self.option.reload_backlogs {
            self.reload_backlogs().await?;
            mgr_report.active_backlogs = self.backlogs.read().await.len();
        }

        // initial report
        _ = report_sender.send(mgr_report.clone()).await;

        // debug!(self.directive.id, "listening for event");

        loop {
            tokio::select! {
                _ = cancel_rx.recv() => {
                    debug!(directive.id = self.directive.id, "cancel signal received, exiting manager thread");
                    drop(upstream);
                    drop(report);
                    sleep(Duration::from_secs(3)).await; // give time for inflight event to be processed
                    drop(delete_rx);
                    if self.option.reload_backlogs {
                        clean_deleted().await;
                        let backlogs = self.backlogs.read().await;
                        if  backlogs.len() > 0 {
                            let v = &*backlogs;
                            info!(self.directive.id, "saving {} backlogs to disk", v.len());
                            if let Err(err) = Manager::save(false, self.directive.id, v.to_vec()).await {
                                error!(directive.id = self.directive.id, "error saving backlogs: {:?}", err);
                            } else {
                                debug!(directive.id = self.directive.id, "{} backlogs saved", backlogs.len());
                            }
                        }
                    }
                    break;
                }
                _ = report.tick() => {
                    let length = {
                        let r = self.backlogs.read().await;
                        r.len()
                    };
                    let prev = mgr_report.active_backlogs;
                    mgr_report.active_backlogs = length;

                    if mgr_report.active_backlogs != prev {
                        let _ = report_sender.try_send(mgr_report.clone());
                    }
                },
                _ = delete_rx.recv() => {
                    clean_deleted().await;
                },
                res = upstream.recv() => {
                    let mut event = match res {
                        Ok(evt) => evt,
                        Err(RecvError::Lagged(n)) => {
                            // here's the main mechanism to allow lagged managers to catch up
                            warn!(directive.id = self.directive.id, "event receiver lagged and skipped {} events", n);
                            continue;
                        }
                        Err(RecvError::Closed) => {
                            debug!(directive.id = self.directive.id, "event receiver closed");
                            continue;
                        }
                    };

                    // 99.99% of events should be filtered out here
                    if
                        (contains_pluginrule &&
                            !rule::quick_check_plugin_rule(&sid_pairs, &event)) ||
                        (contains_taxorule && !rule::quick_check_taxo_rule(&taxo_pairs, &event))
                    {
                        trace!(directive.id = self.directive.id, event.id, "failed quick check");
                        continue;
                    }

                    let manager_span = info_span!("manager processing", directive.id = self.directive.id, event.id);
                    tracer::set_parent_from_event(&manager_span, &event);

                    let _ = manager_span.enter();
                    debug!(directive.id = self.directive.id, event.id, "received event");

                    let mut match_found = false;
                    // keep this lock for the entire event recv() loop so the next event will get updated backlogs
                    let mut backlogs = self.backlogs.write().await;

                    debug!(directive.id = self.directive.id, event.id, "total backlogs {}", backlogs.len());

                    tracer::store_parent_into_event(&manager_span, &mut event);

                    if !backlogs.is_empty() && downstream_tx.send(event.clone()).is_ok() {
                        debug!(directive.id = self.directive.id, event.id, "event sent downstream");

                        let timeout_duration = match self.load_param.queue_mode {
                            QueueMode::Unbounded => Duration::from_secs(31337), // 8 hours, simulate infinite wait
                            QueueMode::Bounded => self.load_param.max_wait,
                        };

                        let overload = self.option.publisher.len() > self.load_param.limit_cap;
                        mgr_report.timedout_backlogs = 0;

                        // check the result, break as soon as there's a match
                        for b in backlogs.iter() {
                            let mut v = b.found_channel.locked_rx.lock().await;
                            if timeout(timeout_duration, v.changed()).await.is_ok() {
                                if *v.borrow() {
                                match_found = true;
                                debug!(directive.id = self.directive.id, event.id, backlog.id = b.id, "found existing backlog that consumes the event");
                                break;
                                }
                            } else {
                                mgr_report.timedout_backlogs += 1;
                                if overload {
                                    // over capacity, no need to check for more timeouts
                                    // this mimics the non-blocking send in go when the queue is full
                                    break;
                                }
                            }
                        }
                    } else {
                        debug!(directive.id = self.directive.id, event.id, "no backlog to consume the event");
                        // downstream_tx.send above can only fail when there's only 1 backlog, and it has exited it's event receiver,
                        // but mgr_delete_rx hasn't run yet before locked_backlogs lock was obtained here.
                        // it is ok therefore to continue evaluating this event as a potential trigger for a new backlog
                    }

                    if match_found {
                        continue;
                    }

                    // timeout should not be treated as no match since it could trigger a duplicate backlog
                    if mgr_report.timedout_backlogs > 0 {
                                debug!(directive.id = self.directive.id, event.id, "{} backlog timeouts, skipping this event", mgr_report.timedout_backlogs);
                        continue;
                    }

                    // new backlog, error here should means fatal for this directive and we should exit

                    let res = self.new_backlog(&event).await;
                    if let Err(e) = res {
                        error!(directive.id = self.directive.id, event.id, "exiting, cannot create new backlog: {}", e);
                        break; // main loop
                    };

                    if let Ok(Some(b)) = res {
                        let arced = Arc::new(b);
                        let clone = Arc::clone(&arced);
                        backlogs.push(arced);
                        let _detached = self.start_backlog(Some(event.clone()), clone).await;
                    }
                }
            }
        }
        Ok(())
    }

    async fn new_backlog(&self, event: &NormalizedEvent) -> Result<Option<Backlog>> {
        // returns error only on fatal condition, non-fatal should return Ok(None)
        let first_rule = self
            .directive
            .rules
            .iter()
            .filter(|v| v.stage == 1)
            .take(1)
            .last()
            .ok_or_else(|| anyhow!("directive {} doesn't have first stage", self.directive.id))?;

        if !first_rule.does_event_match(&self.option.assets, event, false) {
            debug!(
                directive.id = self.directive.id,
                event.id, "event doesn't match first rule"
            );
            return Ok(None);
        }
        debug!(
            directive.id = self.directive.id,
            event.id, "creating new backlog"
        );

        let mut opt = self.get_backlog_opt()?;
        opt.event = Some(event);
        let res = backlog::Backlog::new(&opt).await;
        match res {
            Ok(b) => Ok(Some(b)),
            Err(err) => {
                error!(
                    directive.id = self.directive.id,
                    event.id, "cannot create new backlog: {}", err
                );
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{directive, manager};

    use super::*;
    use tokio::{sync::broadcast::Sender, task, time::sleep};
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_manager() {
        let directives = directive::load_directives(
            true,
            Some(vec!["directives".to_string(), "directive5".to_string()]),
        )
        .unwrap();
        let (event_tx, _) = broadcast::channel(10);
        let (cancel_tx, _) = broadcast::channel::<()>(1);
        let (report_tx, mut report_rx) = mpsc::channel::<manager::ManagerReport>(directives.len());

        let get_opt = move |c: Sender<()>,
                            e: Sender<NormalizedEvent>,
                            r: mpsc::Sender<ManagerReport>,
                            directives: Vec<Directive>| {
            let (backpressure_tx, _) = mpsc::channel::<()>(8);
            let (resptime_tx, _) = mpsc::channel::<f64>(128);

            let assets =
                Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
            let intels = Arc::new(
                crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap(),
            );
            let vulns = Arc::new(
                crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap(),
            );
            ManagerOpt {
                test_env: true,
                reload_backlogs: true,
                directives,
                assets,
                intels,
                vulns,
                intel_private_ip: false,
                max_delay: 0,
                min_alarm_lifetime: 0,
                backpressure_tx,
                cancel_tx: c,
                resptime_tx,
                publisher: e,
                default_status: "Open".to_string(),
                default_tag: "Identified Threat".to_string(),
                med_risk_min: 3,
                med_risk_max: 6,
                report_tx: r,
                max_eps: 1000,
                max_queue: 100,
            }
        };

        let run_manager = |directives: Vec<Directive>| {
            let opt = get_opt(
                cancel_tx.clone(),
                event_tx.clone(),
                report_tx.clone(),
                directives,
            );
            task::spawn(async {
                let m = Manager::new(opt).unwrap();
                _ = m.start(1).await;
            })
        };

        let _handle = run_manager(directives.clone());

        let _report_receiver = task::spawn(async move {
            if report_rx.recv().await.is_some() {
                debug!("report received");
            }
        });

        // test comparing report
        let rpt1 = ManagerReport {
            id: 1,
            active_backlogs: 1,
            timedout_backlogs: 0,
        };
        let mut rpt2 = ManagerReport {
            id: 1,
            active_backlogs: 1,
            timedout_backlogs: 0,
        };
        assert!(rpt1 == rpt2);
        rpt2.active_backlogs = 2;
        assert!(rpt1 != rpt2);

        let mut evt = NormalizedEvent {
            plugin_id: 31337,
            plugin_sid: 2,
            custom_label1: "label".to_string(),
            custom_data1: "data".to_string(),
            ..Default::default()
        };

        sleep(Duration::from_millis(1000)).await;

        // unmatched event
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("failed quick check"));

        // matched event but not on the first rule
        evt.plugin_id = 1337;
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
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
        sleep(Duration::from_millis(500)).await;
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
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("report received"));

        // create another backlog
        evt.plugin_sid = 1;
        evt.id = "6".to_string();
        evt.timestamp = chrono::Utc::now();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("creating new backlog"));
        sleep(Duration::from_millis(500)).await;

        // cancel signal, should also trigger saving to disk
        _ = cancel_tx.send(());
        sleep(Duration::from_millis(4000)).await;
        assert!(logs_contain("1 backlogs saved"));
        assert!(logs_contain("backlog manager exiting"));

        // successful loading from disk
        let _handle = run_manager(directives.clone());
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("reloading old backlog"));

        // overloading the channel capacity
        for _ in 0..200 {
            event_tx.send(evt.clone()).unwrap();
        }
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("event receiver lagged"));

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
}
