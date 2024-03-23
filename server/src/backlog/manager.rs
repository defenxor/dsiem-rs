use std::{io, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use spawner::LazyLoaderConfig;
use tokio::{
    sync::{broadcast, mpsc, oneshot, Mutex, RwLock},
    task,
    time::{interval, interval_at, sleep, timeout, Instant},
};
use tracing::{debug, error, info, info_span};

use super::{Backlog, BacklogOpt, BacklogState};
use crate::{event::NormalizedEvent, tracer, watchdog::REPORT_INTERVAL_IN_SECONDS};

const BACKLOGMGR_DOWNSTREAM_QUEUE_SIZE: usize = 64;

pub mod spawner;
pub(super) mod storage;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct ManagerReport {
    pub id: u64,
    pub active_backlogs: usize,
    pub timedout_backlogs: usize,
    pub matched_events: usize,
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

#[derive(Clone)]
pub struct ManagerOpt {
    pub backlog_option: BacklogOpt,
    pub test_env: bool,
    pub reload_backlogs: bool,
    pub lazy_loader: Option<LazyLoaderConfig>,
    pub max_delay: i64,
    pub cancel_tx: broadcast::Sender<()>,
    pub resptime_tx: mpsc::Sender<f64>,
    pub report_tx: mpsc::Sender<ManagerReport>,
    pub load_param: OpLoadParameter,
}

#[derive(Clone)]
pub struct BacklogManager {
    option: ManagerOpt,
    pub id: u64,
    delete_tx: mpsc::Sender<()>,
    delete_rx: Arc<Mutex<mpsc::Receiver<()>>>,
    downstream_tx: broadcast::Sender<NormalizedEvent>,
    backlogs: Arc<RwLock<Vec<Arc<Backlog>>>>,
    upstream_rx: Arc<Mutex<mpsc::Receiver<NormalizedEvent>>>,
}

impl BacklogManager {
    pub fn new(option: ManagerOpt, upstream_rx: Arc<Mutex<mpsc::Receiver<NormalizedEvent>>>) -> BacklogManager {
        // this channel is a one-to-many channel between backlog manager and its
        // backlogs there's no need for large capacity since there's already a
        // configurable queue in upstream the size of this channel also linearly
        // affects the number of directives that can be load given the same memory
        // resources

        let (downstream_tx, _) = broadcast::channel(BACKLOGMGR_DOWNSTREAM_QUEUE_SIZE);
        let (delete_tx, delete_rx) = mpsc::channel::<()>(128);
        let backlogs = Arc::new(RwLock::new(vec![]));
        let id = option.backlog_option.directive.id;
        BacklogManager {
            option,
            delete_tx,
            delete_rx: Arc::new(Mutex::new(delete_rx)),
            downstream_tx,
            backlogs,
            upstream_rx,
            id,
        }
    }

    async fn start_backlog(&self, evt: Option<NormalizedEvent>, backlog: Arc<Backlog>) {
        let rx = self.downstream_tx.subscribe();
        let max_delay = self.option.max_delay;
        let resptime_tx = self.option.resptime_tx.clone();
        let dir_id = self.id;
        task::spawn(async move {
            info!(directive.id = dir_id, backlog.id, "starting backlog");
            if let Err(e) = backlog.start(rx, evt, resptime_tx, max_delay).await {
                error!(directive.id = dir_id, backlog.id, "backlog exited with an error: {}", e)
            }
        });
    }

    async fn load_from_storage(&self) -> Result<()> {
        let mut backlogs = self.backlogs.write().await;
        let res = storage::load(self.option.test_env, self.id).await;
        match res {
            Err(e) => {
                for cause in e.chain() {
                    if let Some(e) = cause.downcast_ref::<io::Error>() {
                        if e.kind() != io::ErrorKind::NotFound {
                            info!(directive.id = self.id, "cannot load backlogs: {:?}", e);
                        }
                    }
                }
            }
            Ok(load_result) => {
                if !load_result.is_empty() {
                    info!(directive.id = self.id, "reloading old backlog");
                }
                for b in load_result.into_iter() {
                    // perform all steps in backlog::new here
                    let id = &b.id.clone();
                    let opt = self.get_backlog_opt();
                    let res = Backlog::runnable_version(opt, b);
                    match res {
                        Err(e) => {
                            error!(directive.id = self.id, backlog.id = id, "cannot recreate backlog: {}", e);
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
        BacklogOpt { event: None, delete_tx: Some(self.delete_tx.clone()), ..self.option.backlog_option.clone() }
    }

    pub async fn start(&self, ready_tx: oneshot::Sender<()>) -> Result<()> {
        // lock the rx channel asap
        // if this fails, it means another instance is already running and we should
        // abort
        let mut upstream_rx = self.upstream_rx.try_lock().map_err(|e| {
            error!(
                directive.id = self.id,
                "another instance is already running for this directive ID, exiting this one"
            );
            e
        })?;

        let mut cancel_rx = self.option.cancel_tx.subscribe();
        let downstream_tx = self.downstream_tx.clone();

        let report_sender = self.option.report_tx.clone();
        let mut report = interval(Duration::from_secs(REPORT_INTERVAL_IN_SECONDS));

        let mut mgr_report = ManagerReport { id: self.id, active_backlogs: 0, timedout_backlogs: 0, matched_events: 0 };
        let mut prev_matched_events = mgr_report.matched_events;

        let clean_deleted = || async {
            let mut backlogs = self.backlogs.write().await;
            debug!(directive.id = self.id, "cleaning deleted backlog if any");
            backlogs.retain(|x| {
                let s = x.state.lock();
                *s == BacklogState::Created || *s == BacklogState::Running
            });
        };

        if self.option.reload_backlogs {
            self.load_from_storage().await?;
            mgr_report.active_backlogs = self.backlogs.read().await.len();
        }

        // initial report
        _ = report_sender.send(mgr_report.clone()).await;

        let mut delete_rx = self.delete_rx.lock().await;

        // if the option is set, activate idle_timer to exit the manager thread when
        // there's no backlog after the specified minutes
        let (mut checker, mut idle_timeout) = if let Some(reg) = self.option.lazy_loader.as_ref() {
            debug!(directive.id = self.id, "setting timers for idle timer checks");
            reg.cache.insert(self.id, ());
            let tm = reg.get_idle_timeout();
            (
                interval(Duration::from_secs(reg.get_idle_timeout_checker_interval())),
                interval_at(Instant::now() + Duration::from_secs(tm), Duration::from_secs(tm)),
            )
        } else {
            (
                // TODO: needs more elegant way of disabling checker and idle_timeout here
                interval(Duration::from_secs(9001)), // 2.5 hours
                interval(Duration::from_secs(9001)),
            )
        };

        // notify only after cache entry is inserted
        debug!("notifying spawner that backlog manager is ready");
        ready_tx.send(()).map_err(|e| anyhow!("cannot send ready signal: {:?}", e))?;

        debug!(directive.id = self.id, "listening for event");

        loop {
            tokio::select! {
                biased;
                _ = cancel_rx.recv() => {
                    debug!(directive.id = self.id, "cancel signal received, exiting manager thread");
                    upstream_rx.close();
                    drop(report);
                    sleep(Duration::from_secs(3)).await; // give time for inflight event to be processed
                    drop(delete_rx);
                    if self.option.reload_backlogs {
                        clean_deleted().await;
                        let backlogs = self.backlogs.read().await;
                        if  backlogs.len() > 0 {
                            let v = &*backlogs;
                            info!(self.id, "saving {} backlogs to disk", v.len());
                            if let Err(err) = storage::save(self.option.test_env, self.id, v.to_vec()).await {
                                error!(directive.id = self.id, "error saving backlogs: {:?}", err);
                            } else {
                                debug!(directive.id = self.id, "{} backlogs saved", backlogs.len());
                            }
                        }
                    }
                    break;
                },
                _ = delete_rx.recv() => {
                    clean_deleted().await;
                },
                _ = checker.tick() => {
                    if self.option.lazy_loader.is_none() {
                        continue;
                    }
                    let backlogs = self.backlogs.read().await;
                    if !backlogs.is_empty() {
                        debug!(directive.id = self.id, "backlogs is not empty resetting idle timeout");
                        idle_timeout.reset();
                    }
                },
                _ = idle_timeout.tick() => {
                        if self.option.lazy_loader.is_none() {
                            continue;
                        }
                        // note: the upstream_rx should NOT be closed here, so it can still be reuse by future instances
                        info!(directive.id = self.id, "idle timeout reached, exiting backlog manager thread");
                        if let Some(v) = self.option.lazy_loader.as_ref() {
                            // note: the upstream_rx should NOT be closed here, so it can still be reuse by future
                            // instances, so instead we'll just drop the lock
                            //
                            // the order between cache invalidation and dropping the lock here doesn't matter that much
                            // it will just move the location of potential event loss during the transition from this
                            // instance to the next. That's only applicable if there's incoming event while we're
                            // exiting this one.
                            v.cache.invalidate(&self.id);
                            // events that are in-flight here could potentially create a new backlog manager,
                            // which may not be able to lock the upstream_rx yet before this next line is executed.
                            drop(upstream_rx);
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

                    // send only when there's a change
                    if mgr_report.active_backlogs != prev || mgr_report.matched_events != prev_matched_events {
                        let _ = report_sender.try_send(mgr_report.clone());
                    }
                    // save prev value then reset
                    prev_matched_events = mgr_report.matched_events;
                    mgr_report.matched_events = 0;
                },
                Some(mut event) = upstream_rx.recv() => {

                    let backlog_mgr_span = info_span!("backlog manager processing", directive.id = self.id, event.id);
                    tracer::set_parent_from_event(&backlog_mgr_span, &event);

                    let _ = backlog_mgr_span.enter();
                    debug!(directive.id = self.id, event.id, "received event");
                    mgr_report.matched_events += 1;

                    let mut match_found = false;
                    // keep this lock for the entire event recv() loop so the next event will get updated backlogs
                    let mut backlogs = self.backlogs.write().await;

                    debug!(directive.id = self.id, event.id, "total backlogs {}", backlogs.len());

                    tracer::store_parent_into_event(&backlog_mgr_span, &mut event);

                    if !backlogs.is_empty() && downstream_tx.send(event.clone()).is_ok() {
                        debug!(directive.id = self.id, event.id, "event sent downstream");

                        let timeout_duration = match self.option.load_param.queue_mode {
                            QueueMode::Unbounded => Duration::from_secs(31337), // 8 hours, simulate infinite wait
                            QueueMode::Bounded => self.option.load_param.max_wait,
                        };

                        mgr_report.timedout_backlogs = 0;

                        // check the result, break as soon as there's a match
                        for b in backlogs.iter() {
                            let mut v = b.found_channel.locked_rx.lock().await;
                            if timeout(timeout_duration, v.changed()).await.is_ok() {
                                if *v.borrow() {
                                match_found = true;
                                debug!(
                                    directive.id = self.id,
                                    event.id,
                                    backlog.id = b.id,
                                    "found existing backlog that consumes the event"
                                );
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
                        debug!(directive.id = self.id, event.id, "no backlog to consume the event");
                        // downstream_tx.send above can only fail when there's only 1 backlog, and it has exited
                        // it's event receiver, but mgr_delete_rx hasn't run yet before locked_backlogs lock was
                        // obtained here. It is ok therefore to continue evaluating this event as a potential
                        // trigger for a new backlog
                    }

                    if match_found {
                        continue;
                    }

                    // timeout should not be treated as no match since it could trigger a duplicate backlog
                    if mgr_report.timedout_backlogs > 0 {
                        debug!(
                            directive.id = self.id, event.id,
                            "{} backlog timeouts, skip creating new backlog based on this event",
                            mgr_report.timedout_backlogs
                        );
                        continue;
                    }

                    // new backlog, error here should means fatal for this directive and we should exit

                    let res = self.new_backlog(&event);
                    if let Err(e) = res {
                        error!(directive.id = self.id, event.id, "exiting, cannot create new backlog: {}", e);
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
            .option
            .backlog_option
            .directive
            .rules
            .iter()
            .find(|v| v.stage == 1)
            .ok_or_else(|| anyhow!("directive {} doesn't have first stage", self.id))?;

        if !first_rule.does_event_match(&self.option.backlog_option.asset, event, false) {
            debug!(directive.id = self.id, event.id, "event doesn't match first rule");
            return Ok(None);
        }
        debug!(directive.id = self.id, event.id, "creating new backlog");

        let mut opt = self.get_backlog_opt();
        opt.event = Some(Arc::new(event.clone()));
        let res = Backlog::new(&opt);
        match res {
            Ok(b) => Ok(Some(b)),
            Err(err) => {
                error!(directive.id = self.id, event.id, "cannot create new backlog: {}", err);
                Ok(None)
            }
        }
    }
}
