use std::{io, sync::Arc, time::Duration};

use tokio::time::{interval_at, Instant};
use tokio::{
    sync::{broadcast, mpsc, oneshot, Mutex, RwLock},
    task,
    time::{interval, sleep, timeout},
};
use tracing::{debug, error, info, info_span};

use anyhow::{anyhow, Result};

use crate::manager::option::LazyLoaderConfig;
use crate::{
    asset::NetworkAssets, directive::Directive, event::NormalizedEvent, intel::IntelPlugin,
    log_writer::LogWriterMessage, manager::ManagerOpt, tracer, vuln::VulnPlugin,
};

use super::{Backlog, BacklogOpt, BacklogState};

const BACKLOGMGR_DOWNSTREAM_QUEUE_SIZE: usize = 64;

mod storage;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct ManagerReport {
    pub id: u64,
    pub active_backlogs: usize,
    pub timedout_backlogs: usize,
}

#[derive(Clone)]
pub struct OpLoadParameter {
    pub limit_cap: usize,
    pub max_wait: Duration,
    pub queue_mode: QueueMode,
}

#[derive(Clone, PartialEq)]
pub enum QueueMode {
    Unbounded,
    Bounded,
}

pub struct BacklogManager {
    pub lazy_loader: Option<LazyLoaderConfig>,
    pub max_delay: i64,
    pub resptime_tx: mpsc::Sender<f64>,
    pub reload_backlogs: bool,
    pub cancel_tx: broadcast::Sender<()>,
    pub report_tx: mpsc::Sender<ManagerReport>,
    pub directive: Directive,
    load_param: OpLoadParameter,
    report_interval: u64,
    backlogs: Arc<RwLock<Vec<Arc<Backlog>>>>,
    downstream_tx: broadcast::Sender<NormalizedEvent>,
    upstream_rx: Arc<Mutex<mpsc::Receiver<NormalizedEvent>>>,
    bp_tx: mpsc::Sender<()>,
    delete_tx: mpsc::Sender<()>,
    delete_rx: Arc<Mutex<mpsc::Receiver<()>>>,
    assets: Arc<NetworkAssets>,
    intels: Arc<IntelPlugin>,
    vulns: Arc<VulnPlugin>,
    intel_private_ip: bool,
    default_status: String,
    default_tag: String,
    med_risk_min: u8,
    med_risk_max: u8,
    min_alarm_lifetime: i64,
    log_tx: crossbeam_channel::Sender<LogWriterMessage>,
}

impl BacklogManager {
    pub fn new<'a>(
        manager_option: &'a ManagerOpt,
        directive: Directive,
        load_param: &'a OpLoadParameter,
        log_tx: &crossbeam_channel::Sender<LogWriterMessage>,
        report_interval: &u64,
        upstream_rx: Arc<Mutex<mpsc::Receiver<NormalizedEvent>>>,
    ) -> BacklogManager {
        // this channel is a one-to-many channel between backlog manager and its backlogs
        // there's no need for large capacity since there's already a configurable queue in upstream
        // the size of this channel also linearly affects the number of directives that can be load given the same memory resources
        let (downstream_tx, _) = broadcast::channel(BACKLOGMGR_DOWNSTREAM_QUEUE_SIZE);
        let (delete_tx, delete_rx) = mpsc::channel::<()>(128);

        let log_tx = log_tx.clone();
        BacklogManager {
            lazy_loader: manager_option.lazy_loader.clone(),
            max_delay: manager_option.max_delay,
            resptime_tx: manager_option.resptime_tx.clone(),
            reload_backlogs: manager_option.reload_backlogs,
            cancel_tx: manager_option.cancel_tx.clone(),
            report_tx: manager_option.report_tx.clone(),
            directive,
            load_param: load_param.to_owned(),
            report_interval: *report_interval,
            backlogs: Arc::new(RwLock::new(vec![])),
            downstream_tx,
            upstream_rx,
            bp_tx: manager_option.backpressure_tx.clone(),
            delete_tx,
            delete_rx: Arc::new(Mutex::new(delete_rx)),
            assets: manager_option.assets.clone(),
            intels: manager_option.intels.clone(),
            vulns: manager_option.vulns.clone(),
            intel_private_ip: manager_option.intel_private_ip,
            default_status: manager_option.default_status.clone(),
            default_tag: manager_option.default_status.clone(),
            med_risk_min: manager_option.med_risk_min,
            med_risk_max: manager_option.med_risk_max,
            min_alarm_lifetime: manager_option.min_alarm_lifetime,
            log_tx,
        }
    }

    async fn start_backlog(&self, evt: Option<NormalizedEvent>, backlog: Arc<Backlog>) {
        let rx = self.downstream_tx.subscribe();
        let max_delay = self.max_delay;
        let resptime_tx = self.resptime_tx.clone();
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

    async fn load_from_storage(&self) -> Result<()> {
        let mut backlogs = self.backlogs.write().await;
        let res = storage::load(false, self.directive.id).await;
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
                    let opt = self.get_backlog_opt();
                    let res = Backlog::runnable_version(opt, b);
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

    fn get_backlog_opt(&self) -> BacklogOpt {
        BacklogOpt {
            asset: self.assets.clone(),
            bp_tx: self.bp_tx.clone(),
            delete_tx: self.delete_tx.clone(),
            intels: self.intels.clone(),
            vulns: self.vulns.clone(),
            min_alarm_lifetime: self.min_alarm_lifetime,
            default_status: &self.default_status,
            default_tag: &self.default_tag,
            med_risk_min: self.med_risk_min,
            med_risk_max: self.med_risk_max,
            intel_private_ip: self.intel_private_ip,
            directive: &self.directive,
            log_tx: self.log_tx.clone(),
            event: None,
        }
    }

    pub async fn start(&self, ready_tx: oneshot::Sender<()>) -> Result<()> {
        let mut cancel_rx = self.cancel_tx.subscribe();
        let downstream_tx = self.downstream_tx.clone();

        let report_sender = self.report_tx.clone();
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
                let s = x.state.lock();
                *s == BacklogState::Created || *s == BacklogState::Running
            });
        };

        if self.reload_backlogs {
            self.load_from_storage().await?;
            mgr_report.active_backlogs = self.backlogs.read().await.len();
        }

        // initial report
        _ = report_sender.send(mgr_report.clone()).await;

        let mut upstream_rx = self.upstream_rx.lock().await;
        let mut delete_rx = self.delete_rx.lock().await;

        debug!("about to send ready signal");
        ready_tx
            .send(())
            .map_err(|e| anyhow!("cannot send ready signal: {:?}", e))?;

        debug!("about to check interval timers");

        // if the option is set, activate idle_timer to exit the manager thread when there's no backlog after the specified minutes
        let (mut checker, mut idle_timeout) = if let Some(reg) = self.lazy_loader.as_ref() {
            debug!(
                directive.id = self.directive.id,
                "setting timers for idle timer checks"
            );
            reg.cache.insert(self.directive.id, ());
            let tm = reg.get_idle_timeout();
            (
                interval(Duration::from_secs(reg.get_idle_timeout_checker_interval())),
                interval_at(
                    Instant::now() + Duration::from_secs(tm),
                    Duration::from_secs(tm),
                ),
            )
        } else {
            (
                // TODO: needs more elegant way of disabling checker and idle_timeout here
                interval(Duration::from_secs(9001)), // 2.5 hours
                interval(Duration::from_secs(9001)),
            )
        };

        debug!(directive.id = self.directive.id, "listening for event");

        loop {
            tokio::select! {
                biased;
                _ = cancel_rx.recv() => {
                    debug!(directive.id = self.directive.id, "cancel signal received, exiting manager thread");
                    upstream_rx.close();
                    drop(report);
                    sleep(Duration::from_secs(3)).await; // give time for inflight event to be processed
                    drop(delete_rx);
                    if self.reload_backlogs {
                        clean_deleted().await;
                        let backlogs = self.backlogs.read().await;
                        if  backlogs.len() > 0 {
                            let v = &*backlogs;
                            info!(self.directive.id, "saving {} backlogs to disk", v.len());
                            if let Err(err) = storage::save(false, self.directive.id, v.to_vec()).await {
                                error!(directive.id = self.directive.id, "error saving backlogs: {:?}", err);
                            } else {
                                debug!(directive.id = self.directive.id, "{} backlogs saved", backlogs.len());
                            }
                        }
                    }
                    break;
                },
                _ = delete_rx.recv() => {
                    clean_deleted().await;
                },
                _ = checker.tick() => {
                    if self.lazy_loader.is_none() {
                        continue;
                    }
                    let backlogs = self.backlogs.read().await;
                    if !backlogs.is_empty() {
                        debug!(directive.id = self.directive.id, "backlogs is not empty resetting idle timeout");
                        idle_timeout.reset();
                    }
                },
                _ = idle_timeout.tick() => {
                        if self.lazy_loader.is_none() {
                            continue;
                        }
                        info!(directive.id = self.directive.id, "idle timeout reached, exiting backlog manager thread");
                        upstream_rx.close();
                        if let Some(v) = self.lazy_loader.as_ref() {
                            v.cache.invalidate(&self.directive.id);
                        }
                        break;
                },
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
                Some(mut event) = upstream_rx.recv() => {

                    let backlog_mgr_span = info_span!("backlog manager processing", directive.id = self.directive.id, event.id);
                    tracer::set_parent_from_event(&backlog_mgr_span, &event);

                    let _ = backlog_mgr_span.enter();
                    debug!(directive.id = self.directive.id, event.id, "received event");

                    let mut match_found = false;
                    // keep this lock for the entire event recv() loop so the next event will get updated backlogs
                    let mut backlogs = self.backlogs.write().await;

                    debug!(directive.id = self.directive.id, event.id, "total backlogs {}", backlogs.len());

                    tracer::store_parent_into_event(&backlog_mgr_span, &mut event);

                    if !backlogs.is_empty() && downstream_tx.send(event.clone()).is_ok() {
                        debug!(directive.id = self.directive.id, event.id, "event sent downstream");

                        let timeout_duration = match self.load_param.queue_mode {
                            QueueMode::Unbounded => Duration::from_secs(31337), // 8 hours, simulate infinite wait
                            QueueMode::Bounded => self.load_param.max_wait,
                        };

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
                                //if overload {
                                    // over capacity, no need to check for more timeouts
                                    // this mimics the non-blocking send in go when the queue is full
                                  //  break;
                                //}
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
                                debug!(directive.id = self.directive.id, event.id, "{} backlog timeouts, skip creating new backlog based on this event", mgr_report.timedout_backlogs);
                        continue;
                    }

                    // new backlog, error here should means fatal for this directive and we should exit

                    let res = self.new_backlog(&event);
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
                },
            }
        }
        Ok(())
    }

    fn new_backlog(&self, event: &NormalizedEvent) -> Result<Option<Backlog>> {
        // returns error only on fatal condition, non-fatal should return Ok(None)
        let first_rule = self
            .directive
            .rules
            .iter()
            .filter(|v| v.stage == 1)
            .take(1)
            .last()
            .ok_or_else(|| anyhow!("directive {} doesn't have first stage", self.directive.id))?;

        if !first_rule.does_event_match(&self.assets, event, false) {
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

        let mut opt = self.get_backlog_opt();
        opt.event = Some(event);
        let res = Backlog::new(&opt);
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
