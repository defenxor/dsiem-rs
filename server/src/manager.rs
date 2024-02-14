use std::{ sync::Arc, time::Duration, fs::create_dir_all };

use tracing::{ info, debug, error };

use crate::{
    directive::Directive,
    asset::NetworkAssets,
    event::NormalizedEvent,
    rule,
    backlog::{ self, Backlog, BacklogState },
    intel::IntelPlugin,
    vuln::VulnPlugin,
    utils,
};

use anyhow::{ Result, anyhow };
use tokio::{
    task::{ JoinSet, self },
    sync::{ broadcast, mpsc, RwLock },
    time::{ interval, timeout, sleep },
    fs::{ OpenOptions, read_to_string, self },
    io::{ AsyncWriteExt, self },
};

#[derive(PartialEq, Eq, Hash)]
pub struct ManagerReport {
    pub id: u64,
    pub active_backlogs: usize,
}

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
    pub resptime_tx: mpsc::Sender<Duration>,
    pub publisher: broadcast::Sender<NormalizedEvent>,
    pub default_status: String,
    pub default_tag: String,
    pub med_risk_min: u8,
    pub med_risk_max: u8,
    pub report_tx: mpsc::Sender<ManagerReport>,
}
pub struct Manager {
    option: ManagerOpt,
}

impl Manager {
    pub fn new(option: ManagerOpt) -> Result<Manager> {
        let m = Manager {
            option,
        };
        Ok(m)
    }

    pub async fn load(test_env: bool, directive_id: u64) -> Result<Vec<Backlog>> {
        let backlog_dir = utils::log_dir(test_env)?.join("backlogs");
        let filename = backlog_dir.join(directive_id.to_string() + ".json");
        debug!("loading {} (if it exist)", filename.to_string_lossy());
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
            .open(backlog_dir.join(filename)).await?;

        let mut backlogs = vec![];
        for b in source.into_iter() {
            let saveable = Backlog::saveable_version(b);

            // if extra sanity check for occurrence & stage are needed, they should be done here
            // currently such tests are only during loading in Backlog::runable_version()

            backlogs.push(saveable);
        }

        let s = serde_json::to_string_pretty(&backlogs)? + "\n";
        file.write_all(s.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }
    pub async fn listen(self, report_interval: u64) -> Result<()> {
        info!("backlog manager started");
        // copy this channel to all directive managers
        let bp_sender = self.option.backpressure_tx.clone();
        let mut set = JoinSet::new();
        for directive in self.option.directives {
            let assets = self.option.assets.clone();
            let intels = self.option.intels.clone();
            let vulns = self.option.vulns.clone();
            let sender = self.option.publisher.clone();
            let default_status = self.option.default_status.clone();
            let default_tag = self.option.default_tag.clone();
            let cancel_tx = self.option.cancel_tx.clone();
            let resptime_tx = self.option.resptime_tx.clone();
            let first_rule = directive.rules
                .iter()
                .filter(|v| v.stage == 1)
                .take(1)
                .last()
                .ok_or_else(|| anyhow!("directive {} doesn't have first stage", directive.id))?
                .clone();

            let bp_sender = bp_sender.clone();
            let report_sender = self.option.report_tx.clone();

            set.spawn(async move {
                let (sid_pairs, taxo_pairs) = rule::get_quick_check_pairs(&directive.rules);
                let contains_pluginrule = !sid_pairs.is_empty();
                let contains_taxorule = !taxo_pairs.is_empty();
                let mut upstream = sender.subscribe();
                let mut cancel_rx = cancel_tx.subscribe();
                let (downstream_tx, _) = broadcast::channel(1024);
                let (mgr_delete_tx, mut mgr_delete_rx) = mpsc::channel::<()>(128);

                debug!(directive.id, "listening for event");
                let report_sender = report_sender.clone();
                let mut report = interval(Duration::from_secs(report_interval));
                let mut prev_length = 0;

                let get_opt = || {
                    backlog::BacklogOpt {
                        asset: assets.clone(),
                        bp_tx: bp_sender.clone(),
                        delete_tx: mgr_delete_tx.clone(),
                        intels: intels.clone(),
                        vulns: vulns.clone(),
                        min_alarm_lifetime: self.option.min_alarm_lifetime,
                        default_status: default_status.clone(),
                        default_tag: default_tag.clone(),
                        med_risk_min: self.option.med_risk_min,
                        med_risk_max: self.option.med_risk_max,
                        intel_private_ip: self.option.intel_private_ip,
                        directive: &directive,
                        event: None,
                    }
                };

                let start_backlog = |evt: Option<NormalizedEvent>, b: Arc<Backlog>| {
                    let rx = downstream_tx.subscribe();
                    let max_delay = self.option.max_delay;
                    let resptime_tx = resptime_tx.clone();
                    task::spawn(async move {
                        if let Err(e) = b.start(rx, evt, resptime_tx, max_delay).await {
                            error!(
                                directive.id,
                                b.id,
                                "backlog exited with an error: {:?}",
                                e.to_string()
                            )
                        }
                    })
                };

                let locked_backlogs: RwLock<Vec<Arc<Backlog>>> = RwLock::new(vec![]);
                let clean_deleted = || async {
                    let mut backlogs = locked_backlogs.write().await;
                    info!(directive.id, "cleaning deleted backlog");
                    backlogs.retain(|x| {
                        let s = x.state.read();
                        *s == BacklogState::Created || *s == BacklogState::Running
                    });
                };

                if self.option.reload_backlogs {
                    let mut backlogs = locked_backlogs.write().await;
                    let res = Manager::load(false, directive.id).await;
                    if let Err(e) = res {
                        for cause in e.chain() {
                            if let Some(e) = cause.downcast_ref::<io::Error>() {
                                if e.kind() != io::ErrorKind::NotFound {
                                    debug!(directive.id, "cannot load backlogs: {:?}", e);
                                }
                            }
                        }
                    } else if let Ok(load_result) = res {
                        if !load_result.is_empty() {
                            debug!(directive.id, "reloading old backlog");
                        }
                        for b in load_result.into_iter() {
                            // perform all steps in backlog::new here
                            let id = &b.id.clone();
                            let res = Backlog::runnable_version(get_opt(), b).await;
                            if res.is_err() {
                                error!(
                                    directive.id,
                                    id,
                                    "cannot recreate backlog: {:?}",
                                    res.unwrap_err()
                                );
                                continue;
                            } else if let Ok(b) = res {
                                let arced = Arc::new(b);
                                let clone = Arc::clone(&arced);
                                backlogs.push(arced);
                                let _detached = start_backlog(None, clone);
                            }
                        }
                    }
                    prev_length = backlogs.len();
                }

                // initial report
                _ = report_sender.send(ManagerReport {
                    id: directive.id,
                    active_backlogs: prev_length,
                }).await;

                loop {
                    tokio::select! {
                        _ = cancel_rx.recv() => {
                            debug!(directive.id, "cancel signal received, exiting manager thread");
                            drop(upstream);
                            drop(report);
                            sleep(Duration::from_secs(3)).await; // give time for inflight event to be processed
                            drop(mgr_delete_rx);
                            if self.option.reload_backlogs {
                                clean_deleted().await;
                                let backlogs = locked_backlogs.read().await;
                                if  backlogs.len() > 0 {
                                    let v = &*backlogs;
                                    if let Err(err) = Manager::save(false, directive.id, v.to_vec()).await {
                                        error!(directive.id, "error saving backlogs: {:?}", err);
                                    } else {
                                        debug!(directive.id, "{} backlogs saved", backlogs.len());
                                    }
                                }
                            }
                            break;
                        }
                        _ = report.tick() => {
                            let length = { 
                                let r = locked_backlogs.read().await;
                                r.len()
                            };
                            if length != prev_length && report_sender.try_send(ManagerReport {
                                    id: directive.id,
                                    active_backlogs: length
                                }).is_ok() {
                                prev_length = length;
                            }
                        },
                        _ = mgr_delete_rx.recv() => {
                            clean_deleted().await;
                        },
                        Ok(event) = upstream.recv() => {
                            debug!(directive.id, event.id, "received event");
                            if
                                (contains_pluginrule &&
                                    !rule::quick_check_plugin_rule(&sid_pairs, &event)) ||
                                (contains_taxorule && !rule::quick_check_taxo_rule(&taxo_pairs, &event))
                            {
                                debug!(directive.id, event.id, "failed quick check");
                                continue;
                            }
                    
                            let mut match_found = false;
                            // keep this lock for the entire event recv() loop so the next event will get updated backlogs
                            let mut backlogs = locked_backlogs.write().await;

                            debug!(directive.id, event.id, "total backlogs {}", backlogs.len());

                            if !backlogs.is_empty() {
                                if downstream_tx.send(event.clone()).is_ok() {
                                    debug!(directive.id, event.id, "event sent downstream");
                                    // check the result, break as soon as there's a match
                                    for b in backlogs.iter() {
                                        let mut v = b.found_channel.locked_rx.lock().await;
                                        // timeout is used here since downstream_tx.send() doesn't guarantee there will be a response
                                        // on the found_channel
                                        if timeout(Duration::from_millis(1000), v.changed()).await.is_ok() && *v.borrow() {
                                            match_found = true;
                                            break;
                                        } else {
                                            // timeout or v.borrow() == false
                                        }
                                    }
                                } else {
                                    // this can only happen when there's only 1 backlog, and it has exited it's event receiver, 
                                    // but mgr_delete_rx hasn't run yet before locked_backlogs lock was obtained here.
                                    // it is ok therefore to continue evaluating this event as a potential trigger for a new backlog
                                }
                            }

                            if match_found {
                                debug!(directive.id, event.id, "found existing backlog that consumes the event");
                                continue;
                            }

                            // new backlog, make sure the event match the first rule
                            if !first_rule.does_event_match(&assets, &event, false) {
                                debug!(directive.id, event.id, "event doesn't match first rule");
                                // trace!(" the first rule: {:?}, the event: {:?}", first_rule, &event);
                                continue;
                            }

                            debug!(directive.id, event.id, "creating new backlog");
                            let mut opt = get_opt();
                            opt.event = Some(&event);
                            let res = backlog::Backlog::new(opt).await;
                            if res.is_err() {
                                error!(directive.id, "cannot create backlog: {}", res.unwrap_err());
                            } else if let Ok(b) = res {
                                let arced = Arc::new(b);
                                let clone = Arc::clone(&arced);
                                backlogs.push(arced);
                                let _detached = start_backlog(Some(event), clone);
                            }
                        }

                    }
                }
            });
        }

        while set.join_next().await.is_some() {}
        info!("backlog manager exiting");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{ directive, manager };

    use super::*;
    use tokio::{ time::sleep, task, sync::broadcast::Sender };
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_manager() {
        let directives = directive
            ::load_directives(true, Some(vec!["directives".to_string(), "directive5".to_string()]))
            .unwrap();
        let (event_tx, _) = broadcast::channel(10);
        let (cancel_tx, _) = broadcast::channel::<()>(1);
        let (report_tx, mut report_rx) = mpsc::channel::<manager::ManagerReport>(directives.len());

        let get_opt = move |
            c: Sender<()>,
            e: Sender<NormalizedEvent>,
            r: mpsc::Sender<ManagerReport>,
            directives: Vec<Directive>
        | {
            let (backpressure_tx, _) = mpsc::channel::<()>(8);
            let (resptime_tx, _) = mpsc::channel::<Duration>(128);

            let assets = Arc::new(
                NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap()
            );
            let intels = Arc::new(
                crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap()
            );
            let vulns = Arc::new(
                crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap()
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
            }
        };

        let run_manager = |directives: Vec<Directive>| {
            let opt = get_opt(cancel_tx.clone(), event_tx.clone(), report_tx.clone(), directives);
            task::spawn(async {
                let m = Manager::new(opt).unwrap();
                _ = m.listen(1).await;
            })
        };

        let _handle = run_manager(directives.clone());

        let _report_receiver = task::spawn(async move {
            let res = report_rx.recv().await;
            if res.is_some() {
                debug!("report received");
            }
        });

        // test comparing report
        let rpt1 = ManagerReport {
            id: 1,
            active_backlogs: 1,
        };
        let mut rpt2 = ManagerReport {
            id: 1,
            active_backlogs: 1,
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
        assert!(logs_contain("found existing backlog that consumes the event"));

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
