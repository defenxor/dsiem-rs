use crate::{
    asset::NetworkAssets,
    directive::Directive,
    event::NormalizedEvent,
    intel::{IntelPlugin, IntelResult},
    log_writer::{FileType, LogWriterMessage},
    rule::DirectiveRule,
    tracer, utils,
    vuln::{VulnPlugin, VulnResult},
};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_derive::Serialize;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicI64, AtomicU16, AtomicU8, Ordering::Relaxed},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::{broadcast::Receiver, mpsc::Sender, watch},
    time::{interval, Instant},
};
use tracing::{debug, error, info, info_span, trace, warn, Instrument};

pub mod manager;

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct CustomData {
    pub label: String,
    pub content: String,
}

#[derive(Serialize)]
pub struct SiemAlarmEvent {
    #[serde(rename(serialize = "alarm_id"))]
    id: String,
    stage: u8,
    event_id: String,
}

#[derive(Debug, PartialEq, Default)]
pub enum BacklogState {
    #[default]
    Created,
    Running,
    Stopped,
}

// serialize should only for alarm fields.
// RwLocks are used so that self doesnt have to be mutable
// if it's mutable, backlogs type can't be Vec<Arc<Backlog>> in the manager
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Backlog {
    #[serde(rename(serialize = "alarm_id", deserialize = "alarm_id"))]
    pub id: String,
    pub title: String,
    pub status: String,
    pub tag: String,
    pub kingdom: String,
    pub category: String,
    pub created_time: AtomicI64,
    pub update_time: AtomicI64,
    pub risk: AtomicU8,
    pub risk_class: Mutex<String>,
    pub rules: Vec<DirectiveRule>,
    pub src_ips: Mutex<HashSet<IpAddr>>,
    pub dst_ips: Mutex<HashSet<IpAddr>>,
    pub networks: Mutex<HashSet<String>>,
    #[serde(skip_serializing_if = "is_locked_data_empty")]
    #[serde(default)]
    pub intel_hits: Mutex<HashSet<IntelResult>>,
    #[serde(skip_serializing_if = "is_locked_data_empty")]
    #[serde(default)]
    pub vulnerabilities: Mutex<HashSet<VulnResult>>,
    #[serde(skip_serializing_if = "is_locked_data_empty")]
    #[serde(default)]
    pub custom_data: Mutex<HashSet<CustomData>>,

    #[serde(skip)]
    pub last_srcport: AtomicU16, // copied from event for vuln check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_last_srcport: Option<u16>, // saveable version of last_srcport
    #[serde(skip)]
    pub last_dstport: AtomicU16, // copied from event for vuln check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_last_dstport: Option<u16>, // saveable version of last_dstport

    #[serde(skip)]
    pub all_rules_always_active: bool, // copied from directive
    #[serde(skip)]
    pub priority: u8, // copied from directive, never updated
    #[serde(skip)]
    pub current_stage: AtomicU8,
    #[serde(skip)]
    pub highest_stage: u8, // never updated
    #[serde(skip)]
    pub assets: Arc<NetworkAssets>,
    #[serde(skip)]
    backpressure_tx: Option<Sender<()>>,
    #[serde(skip)]
    delete_channel: DeleteChannel,
    #[serde(skip)]
    pub found_channel: FoundChannel,
    #[serde(skip)]
    pub state: Mutex<BacklogState>,
    #[serde(skip)]
    pub min_alarm_lifetime: i64, // never updated
    #[serde(skip)]
    pub med_risk_min: u8, // never updated
    #[serde(skip)]
    pub med_risk_max: u8, // never updated
    #[serde(skip)]
    pub intels: Option<Arc<IntelPlugin>>,
    #[serde(skip)]
    pub vulns: Option<Arc<VulnPlugin>>,
    #[serde(skip)]
    pub intel_private_ip: bool, // never updated
    #[serde(skip)]
    directive_id: u64, // never updated
    #[serde(skip)]
    log_tx: Option<crossbeam_channel::Sender<LogWriterMessage>>,
}

// This is only used for serialize
fn is_locked_data_empty<T>(s: &Mutex<HashSet<T>>) -> bool {
    let r = s.lock();
    r.is_empty()
}

#[derive(Debug)]
struct DeleteChannel {
    tx: tokio::sync::watch::Sender<bool>,
    rx: tokio::sync::watch::Receiver<bool>,
    to_upstream_manager: Option<tokio::sync::mpsc::Sender<()>>,
}

impl Default for DeleteChannel {
    fn default() -> Self {
        let (tx, rx) = watch::channel(false);
        DeleteChannel {
            tx,
            rx,
            to_upstream_manager: None,
        }
    }
}

// for debugging only, to detect when a backlog is out of scope and deleted
impl Drop for DeleteChannel {
    fn drop(&mut self) {
        trace!("Backlog's delete dropped!");
    }
}

#[derive(Debug)]
pub struct FoundChannel {
    tx: tokio::sync::watch::Sender<bool>,
    pub locked_rx: tokio::sync::Mutex<tokio::sync::watch::Receiver<bool>>,
}

impl Default for FoundChannel {
    fn default() -> Self {
        let (tx, rx) = watch::channel(false);
        FoundChannel {
            tx,
            locked_rx: tokio::sync::Mutex::new(rx),
        }
    }
}

pub struct BacklogOpt<'a> {
    pub directive: &'a Directive,
    pub asset: Arc<NetworkAssets>,
    pub intels: Arc<IntelPlugin>,
    pub vulns: Arc<VulnPlugin>,
    pub event: Option<&'a NormalizedEvent>,
    pub bp_tx: Sender<()>,
    pub delete_tx: Sender<()>,
    pub min_alarm_lifetime: i64,
    pub default_status: &'a str,
    pub default_tag: &'a str,
    pub med_risk_min: u8,
    pub med_risk_max: u8,
    pub intel_private_ip: bool,
    pub log_tx: crossbeam_channel::Sender<LogWriterMessage>,
}

impl Backlog {
    pub fn new(o: &BacklogOpt<'_>) -> Result<Self> {
        let mut backlog = Backlog {
            id: utils::generate_id(),
            title: o.directive.name.clone(),
            kingdom: o.directive.kingdom.clone(),
            category: o.directive.category.clone(),
            status: o.default_status.to_owned(),
            tag: o.default_tag.to_owned(),
            intel_private_ip: o.intel_private_ip,
            current_stage: AtomicU8::new(1),
            priority: o.directive.priority,
            all_rules_always_active: o.directive.all_rules_always_active,
            backpressure_tx: Some(o.bp_tx.clone()),
            log_tx: Some(o.log_tx.clone()),
            directive_id: o.directive.id,

            assets: o.asset.clone(),

            min_alarm_lifetime: o.min_alarm_lifetime,
            med_risk_min: o.med_risk_min,
            med_risk_max: o.med_risk_max,
            state: Mutex::new(BacklogState::Created),
            ..Default::default()
        };
        if let Some(v) = o.event {
            if backlog.title.contains("SRC_IP") {
                let src: String = if let Ok(hostname) = backlog.assets.get_name(&v.src_ip) {
                    hostname
                } else {
                    v.src_ip.to_string()
                };
                backlog.title = backlog.title.replace("SRC_IP", &src);
            }
            if backlog.title.contains("DST_IP") {
                let dst: String = if let Ok(hostname) = backlog.assets.get_name(&v.dst_ip) {
                    hostname
                } else {
                    v.dst_ip.to_string()
                };
                backlog.title = backlog.title.replace("DST_IP", &dst);
            }

            backlog.rules = o.directive.init_backlog_rules(v);
            backlog.highest_stage = backlog
                .rules
                .iter()
                .map(|v| v.stage)
                .max()
                .unwrap_or_default();
        }
        backlog.delete_channel.to_upstream_manager = Some(o.delete_tx.clone());
        backlog.intels = Some(o.intels.clone());
        backlog.vulns = Some(o.vulns.clone());

        if let Some(v) = o.event {
            info!(
                directive.id = o.directive.id,
                backlog.id,
                event.id = v.id,
                "new backlog created"
            );
        }
        Ok(backlog)
    }

    // runable_version produces backlog that manager can start
    pub fn runnable_version(o: BacklogOpt<'_>, loaded: Backlog) -> Result<Self> {
        let mut backlog = Backlog::new(&o)?;
        // verify that we're still based on the same directive
        if backlog.title != loaded.title {
            return Err(anyhow!(
                "different title detected: '{}' vs '{}'",
                backlog.title,
                loaded.title
            ));
        }
        backlog.id = loaded.id;
        backlog.title = loaded.title;
        backlog.created_time = loaded.created_time;
        backlog.update_time = loaded.update_time;
        backlog.risk = loaded.risk;
        backlog.risk_class = loaded.risk_class;
        backlog.src_ips = loaded.src_ips;
        backlog.dst_ips = loaded.dst_ips;
        backlog.networks = loaded.networks;
        backlog.custom_data = loaded.custom_data;
        backlog.intel_hits = loaded.intel_hits;
        backlog.vulnerabilities = loaded.vulnerabilities;

        /*
        new() doesn't set rules unless initialize with an event.
        manager doesnt supply event when calling runnable_version.
        this means whatever rules defined in the directive config will not be applied to
        the output of runnable_version
        */
        backlog.rules = loaded.rules.clone();

        if let Some(v) = loaded.saved_last_srcport {
            backlog.last_srcport = AtomicU16::new(v);
        }
        if let Some(v) = loaded.saved_last_dstport {
            backlog.last_dstport = AtomicU16::new(v);
        }

        for r in backlog.rules.iter_mut() {
            if let Some(v) = r.saved_sticky_diffdata.clone() {
                r.sticky_diffdata = Arc::new(Mutex::new(v));
            }
            if let Some(v) = r.saved_event_ids.clone() {
                r.event_ids = Arc::new(Mutex::new(v));
            }
        }
        backlog.highest_stage = backlog
            .rules
            .iter()
            .map(|v| v.stage)
            .max()
            .unwrap_or_default();
        let lowest_stage = loaded
            .rules
            .iter()
            .filter(|v| {
                let r = v.status.lock();
                r.is_empty()
            })
            .map(|x| x.stage)
            .min();
        if let Some(v) = lowest_stage {
            /* uncomment this block if directive rules are applied to backlog, which for now isn't
            if v > backlog.highest_stage {
                let e = anyhow!(
                    "directive highest stage ({}) is lower than backlog's current stage ({}), skipping this backlog",
                    backlog.highest_stage,
                    v
                );
                error!(backlog.id, "{}", e.to_string());
                return Err(e);
            }
            */
            debug!(
                backlog.id,
                "loaded with current_stage: {}, highest_stage: {}", v, backlog.highest_stage
            );
            backlog.current_stage = AtomicU8::new(v);
        } else {
            let e = anyhow!("cannot determine the current stage, skipping this backlog");
            error!(backlog.id, "{}", e.to_string());
            return Err(e);
        }

        Ok(backlog)
    }

    // saveable_version produces backlog that manager can save to disk
    pub fn saveable_version(running: Arc<Backlog>) -> Self {
        // - status, kingdom, tag, category, created_time are empty;
        let mut backlog = Backlog {
            id: (*running.id).to_string(),
            title: (*running.title).to_string(),
            status: (*running.status).to_string(),
            kingdom: (*running.kingdom).to_string(),
            category: (*running.category).to_string(),
            tag: (*running.tag).to_string(),
            created_time: AtomicI64::new(running.created_time.load(Relaxed)),
            update_time: AtomicI64::new(running.update_time.load(Relaxed)),
            risk: AtomicU8::new(running.risk.load(Relaxed)),
            risk_class: (*running.risk_class.lock()).to_string().into(),
            rules: running.rules.clone(),
            src_ips: (*running.src_ips.lock()).clone().into(),
            dst_ips: (*running.dst_ips.lock()).clone().into(),
            networks: (*running.networks.lock()).clone().into(),
            custom_data: (*running.custom_data.lock()).clone().into(),
            intel_hits: (*running.intel_hits.lock()).clone().into(),
            vulnerabilities: (*running.vulnerabilities.lock()).clone().into(),
            ..Default::default()
        };

        let r = running.last_dstport.load(Relaxed);
        if r != 0 {
            backlog.saved_last_dstport = Some(r);
        }
        let r = running.last_srcport.load(Relaxed);
        if r != 0 {
            backlog.saved_last_srcport = Some(r);
        }
        for rule in backlog.rules.iter_mut() {
            let r = rule.sticky_diffdata.lock();
            if !r.sdiff_int.is_empty() || !r.sdiff_string.is_empty() {
                let v = (*r).clone();
                rule.saved_sticky_diffdata = Some(v);
            }
            let r = rule.event_ids.lock();
            if !r.is_empty() {
                let v = (*r).clone();
                rule.saved_event_ids = Some(v);
            }
        }

        backlog
    }

    async fn handle_expiration(&self) -> Result<()> {
        self.set_rule_status("timeout")?;
        self.update_alarm(false).await?;
        self.delete()
    }

    async fn recv_handler(
        &self,
        event: &NormalizedEvent,
        max_delay: &i64,
        resptime_tx: &Sender<f64>,
    ) -> Result<()> {
        let backlog_span = info_span!(
            "backlog processing",
            directive.id = self.directive_id,
            backlog.id = self.id,
            event.id
        );
        debug!(backlog.id = self.id, event.id, "event received");

        tracer::set_parent_from_event(&backlog_span, event);
        _ = backlog_span.enter();

        let now = Instant::now();

        self.process_new_event(event, *max_delay)
            .instrument(backlog_span)
            .await
            .map_err(|err| anyhow!("error processing event: {}", err))?;

        let l = now.elapsed().as_nanos();
        _ = resptime_tx.try_send(l as f64);

        Ok(())
    }

    pub async fn start(
        &self,
        mut rx: Receiver<NormalizedEvent>,
        initial_event: Option<NormalizedEvent>,
        resptime_tx: Sender<f64>,
        max_delay: i64,
    ) -> Result<()> {
        if let Some(v) = initial_event {
            self.recv_handler(&v, &max_delay, &resptime_tx).await?;
        }
        let mut expiration_checker = interval(Duration::from_secs(10));
        let mut delete_rx = self.delete_channel.rx.clone();
        debug!(self.id, "enter running state");
        self.set_state(BacklogState::Running);
        loop {
            tokio::select! {
                _ = expiration_checker.tick() => {
                    if let Ok((expired, seconds_left)) = self.is_expired() {
                        if expired {
                            debug!(backlog.id = self.id, "backlog expired, setting last stage status to timeout and deleting it");
                            if let Err(e) = self.handle_expiration().await {
                                debug!{backlog.id = self.id, "error updating status and deleting backlog: {}", e.to_string()}
                            }
                        } else {
                            debug!(backlog.id = self.id, "backlog will expire in {} seconds", seconds_left);
                        }
                    }
                },
                Ok(event) = rx.recv() => {
                    // note that Lagged is silently ignored
                    {

                        let r = self.state.lock();
                        if *r != BacklogState::Running {
                            warn!(backlog.id = self.id, event.id, "event received, but backlog state is not running");
                            _ = self.report_to_manager(false);
                            continue;
                        }
                    }
                    _ = self.recv_handler(&event, &max_delay, &resptime_tx).await;

                },
                _ = delete_rx.changed() => {
                    self.set_state(BacklogState::Stopped);
                    debug!(backlog.id = self.id, "backlog delete signal received");
                    if let Some(v) = &self.delete_channel.to_upstream_manager {
                        if let Err(e) = v.send(()).await {
                            debug!{backlog.id = self.id, "error notifying manager about backlog deletion: {:?}", e}
                        }
                    };
                    break
                },
            }
        }
        info!(backlog.id = self.id, "exited running state");
        Ok(())
    }

    fn is_expired(&self) -> Result<(bool, i64)> {
        // this calculates in seconds
        let limit = Utc::now().timestamp() - self.min_alarm_lifetime;
        let curr_rule = self.current_rule()?;
        let start = curr_rule.start_time.lock();
        let timeout = curr_rule.timeout;
        let max_time = *start + (timeout as i64);
        Ok((max_time < limit, max_time - limit))
    }
    fn set_state(&self, s: BacklogState) {
        let mut w = self.state.lock();
        *w = s;
    }

    fn is_time_in_order(&self, ts: &DateTime<Utc>) -> bool {
        let reader = self.current_stage.load(Relaxed);
        let prev_stage_ts = self
            .rules
            .iter()
            .filter(|v| v.stage < reader)
            .map(|v| {
                let r = v.end_time.lock();
                *r
            })
            .max()
            .unwrap_or_default();
        prev_stage_ts <= ts.timestamp()
    }

    pub fn current_rule(&self) -> Result<&DirectiveRule> {
        self.get_rule(None)
    }

    pub fn get_rule(&self, stage: Option<u8>) -> Result<&DirectiveRule> {
        let s = if let Some(v) = stage {
            v
        } else {
            self.current_stage.load(Relaxed)
        };
        self.rules
            .iter()
            .filter(|v| v.stage == s)
            .last()
            .ok_or_else(|| anyhow!("cannot locate the current rule"))
    }

    fn report_to_manager(&self, match_found: bool) -> Result<()> {
        self.found_channel.tx.send(match_found)?;
        Ok(())
    }

    pub async fn process_new_event(&self, event: &NormalizedEvent, max_delay: i64) -> Result<()> {
        let curr_rule = self.current_rule()?;

        let n_string: usize;
        let n_int: usize;
        {
            let reader = curr_rule.sticky_diffdata.lock();
            n_string = reader.sdiff_string.len();
            n_int = reader.sdiff_int.len();
        }

        if !curr_rule.does_event_match(&self.assets, event, true) {
            // if flag is set, check if event match previous stage
            if self.all_rules_always_active && curr_rule.stage != 1 {
                debug!("checking prev rules because all_rules_always_active is on");
                let prev_rules = self
                    .rules
                    .iter()
                    .filter(|v| v.stage < curr_rule.stage)
                    .collect::<Vec<&DirectiveRule>>();
                for r in prev_rules {
                    if !r.does_event_match(&self.assets, event, true) {
                        continue;
                    }
                    // event match previous rule, processing it further here
                    // just add the event to the stage, no need to process other steps in processMatchedEvent
                    debug!(
                        backlog.id = self.id,
                        event.id, r.stage, "previous rule match"
                    );
                    self.append_and_write_event(event, Some(r.stage))?;
                    // also update alarm to sync any changes to customData
                    self.update_alarm(false).await?;
                    debug!(event.id, r.stage, "previous rule consume event");
                    _ = self.report_to_manager(true);
                    return Ok(());
                    // no need to process further rules
                }
            }
            debug!("event doesn't match");

            _ = self.report_to_manager(false);
            return Ok(());
        }

        // if stickydiff is set, there must be added member to sdiff_string or sdiff_int
        if !curr_rule.sticky_different.is_empty() {
            let reader = curr_rule.sticky_diffdata.lock();
            if n_string == reader.sdiff_string.len() && n_int == reader.sdiff_int.len() {
                debug!(
                    "backlog can't find new unique value in stickydiff field {}",
                    curr_rule.sticky_different
                );
                _ = self.report_to_manager(false);
                return Ok(());
            }
        }

        // event match current rule, processing it further here
        debug!("rule stage {} match event", curr_rule.stage);
        _ = self.report_to_manager(true);

        if !self.is_time_in_order(&event.timestamp) {
            // event is out of order, discard but prevent it from triggering new backlog
            warn!("discarded out of order event");
            return Ok(());
        }

        if self.is_under_pressure(event.rcvd_time, max_delay) {
            warn!("backlog is under pressure");
            if let Some(tx) = &self.backpressure_tx {
                if let Err(e) = tx.try_send(()) {
                    warn!("error sending under pressure signal: {}", e);
                }
            }
        }

        debug!("processing matching event");
        self.process_matched_event(event).await
    }

    fn is_stage_reach_max_event_count(&self) -> Result<bool> {
        let curr_rule = self.current_rule()?;
        let reader = curr_rule.event_ids.lock();
        let len = reader.len();
        debug!(
            backlog.id = self.id,
            "current rule stage {} event count {}/{}", curr_rule.stage, len, curr_rule.occurrence
        );
        Ok(len >= curr_rule.occurrence)
    }

    fn set_rule_status(&self, status: &str) -> Result<()> {
        let curr_rule = self.current_rule()?;
        let mut w = curr_rule.status.lock();
        *w = status.to_owned();
        Ok(())
    }
    fn set_rule_endtime(&self, t: DateTime<Utc>) -> Result<()> {
        let curr_rule = self.current_rule()?;
        let mut w = curr_rule.end_time.lock();
        *w = t.timestamp();
        Ok(())
    }
    fn set_rule_starttime(&self, ts: DateTime<Utc>) -> Result<()> {
        let curr_rule = self.current_rule()?;
        let mut w = curr_rule.start_time.lock();
        *w = ts.timestamp();
        Ok(())
    }

    fn update_risk(&self) -> Result<bool> {
        let reader = self.src_ips.lock();
        let src_value = reader
            .iter()
            .map(|v| self.assets.get_value(v))
            .max()
            .unwrap_or_default();
        let reader = self.dst_ips.lock();
        let dst_value = reader
            .iter()
            .map(|v| self.assets.get_value(v))
            .max()
            .unwrap_or_default();

        let prior_risk = self.risk.load(Relaxed);
        let value = std::cmp::max(src_value, dst_value);
        let priority = self.priority;
        let reliability = self.current_rule()?.reliability;
        let risk = (priority * reliability * value) / 25;
        if risk != prior_risk {
            info!(
                backlog.id = self.id,
                "risk changed from {} to {}", prior_risk, risk
            );
            self.risk.swap(risk, Relaxed);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn update_risk_class(&self) {
        let mut w = self.risk_class.lock();
        let risk = self.risk.load(Relaxed);
        *w = if risk < self.med_risk_min {
            "Low".to_string()
        } else if risk >= self.med_risk_min && risk <= self.med_risk_max {
            "Medium".to_string()
        } else {
            "High".to_string()
        };
    }

    fn is_last_stage(&self) -> bool {
        self.current_stage.load(Relaxed) == self.highest_stage
    }

    async fn process_matched_event(&self, event: &NormalizedEvent) -> Result<()> {
        self.append_and_write_event(event, None)?;
        // exit early if the newly added event hasnt caused events_count == occurrence
        // for the current stage
        if !self.is_stage_reach_max_event_count()? {
            debug!("stage max event count not yet reached");
            return Ok(());
        }
        // the new event has caused events_count == occurrence
        debug!("stage max event count reached");
        self.set_rule_status("finished")?;
        self.set_rule_endtime(event.timestamp)?;

        // update risk as needed
        let updated = self.update_risk()?;
        if updated {
            self.update_risk_class();
        }

        debug!(backlog.id = self.id, "checking if this is the last stage");
        // if it causes the last stage to reach events_count == occurrence, delete it
        if self.is_last_stage() {
            info!("reached max stage and occurrence, deleting backlog");
            self.update_alarm(true).await?;
            self.delete()?;
            return Ok(());
        }

        // reach max occurrence, but not in last stage.
        debug!("stage max event count reached, increasing stage and updating alarm");
        // increase stage.
        if self.increase_stage() {
            // set rule startTime for the new stage
            self.set_rule_starttime(event.timestamp)?;
            // stageIncreased, update alarm to publish new stage startTime
            self.update_alarm(true).await?;
        }

        Ok(())
    }

    fn delete(&self) -> Result<()> {
        self.delete_channel.tx.send(true)?;
        Ok(())
    }

    fn increase_stage(&self) -> bool {
        let stage = self.current_stage.load(Relaxed);
        if stage < self.highest_stage {
            self.current_stage.fetch_add(1, Relaxed);
            info!("stage increased to {}", stage + 1);
            true
        } else {
            info!("stage is at the highest level");
            false
        }
    }

    fn append_and_write_event(&self, event: &NormalizedEvent, stage: Option<u8>) -> Result<()> {
        let target_rule = self.get_rule(stage)?;
        {
            let mut w = target_rule.event_ids.lock();
            w.insert(event.id.clone());
            let ttl_events = w.len();
            debug!(
                stage = target_rule.stage,
                "appended event {}/{}", ttl_events, target_rule.occurrence
            );
        }

        const DEFAULT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        {
            let mut w = self.src_ips.lock();
            w.insert(event.src_ip);
            if w.len() > 1 && w.contains(&DEFAULT_IP) {
                w.remove(&DEFAULT_IP);
            }
        }
        {
            let mut w = self.dst_ips.lock();
            w.insert(event.dst_ip);
            if w.len() > 1 && w.contains(&DEFAULT_IP) {
                w.remove(&DEFAULT_IP);
            }
        }

        {
            let mut w = self.custom_data.lock();
            if !event.custom_data1.is_empty() {
                w.insert(CustomData {
                    label: event.custom_label1.clone(),
                    content: event.custom_data1.clone(),
                });
            }
            if !event.custom_data2.is_empty() {
                w.insert(CustomData {
                    label: event.custom_label2.clone(),
                    content: event.custom_data2.clone(),
                });
            }
            if !event.custom_data3.is_empty() {
                w.insert(CustomData {
                    label: event.custom_label3.clone(),
                    content: event.custom_data3.clone(),
                });
            }
        }

        self.set_ports(event);
        self.set_update_time();
        self.append_siem_alarm_events(event, stage)?;
        Ok(())
    }

    fn set_ports(&self, e: &NormalizedEvent) {
        if e.src_port != 0 {
            self.last_srcport.swap(e.src_port, Relaxed);
        }
        if e.dst_port != 0 {
            self.last_dstport.swap(e.dst_port, Relaxed);
        }
    }
    fn set_update_time(&self) {
        self.update_time.swap(Utc::now().timestamp(), Relaxed);
    }

    fn set_created_time(&self) {
        let created_time = self.created_time.load(Relaxed);
        if created_time == 0 {
            let updated_time = self.update_time.load(Relaxed);
            self.created_time.swap(updated_time, Relaxed);
        }
    }

    fn is_under_pressure(&self, rcvd_time: i64, max_delay: i64) -> bool {
        if max_delay == 0 {
            return false;
        }
        // if rcvd_time is in the future, then this always returns false
        if let Some(now) = Utc::now().timestamp_nanos_opt() {
            now - rcvd_time > max_delay
        } else {
            false
        }
    }

    fn update_networks(&self) {
        let mut w = self.networks.lock();
        for v in [&self.src_ips, &self.dst_ips] {
            let r = v.lock();
            for ip in r.iter() {
                if let Some(v) = self.assets.get_asset_networks(ip) {
                    for x in v {
                        w.insert(x);
                    }
                }
            }
        }
    }

    fn append_siem_alarm_events(&self, e: &NormalizedEvent, stage: Option<u8>) -> Result<()> {
        let s = if let Some(v) = stage {
            v
        } else {
            self.current_stage.load(Relaxed)
        };
        let sae = SiemAlarmEvent {
            id: self.id.clone(),
            stage: s,
            event_id: e.id.clone(),
        };
        let s = serde_json::to_string(&sae)? + "\n";
        trace!(
            alarm.id = sae.id,
            stage = sae.stage,
            "appending siem_alarm_events"
        );
        if let Some(sender) = &self.log_tx {
            sender.send(LogWriterMessage {
                data: s,
                file_type: FileType::AlarmEvent,
            })?;
        }
        Ok(())
    }

    async fn update_alarm(&self, check_intvuln: bool) -> Result<()> {
        let risk = self.risk.load(Relaxed);
        if risk == 0 {
            trace!("risk is zero, skip updating alarm");
            return Ok(());
        }
        debug!(check_intvuln, "updating alarm");
        self.set_created_time();
        self.update_networks();

        if check_intvuln {
            if self.intels.is_some() {
                debug!("querying threat intel plugins");
                // dont fail alarm update if there's intel check err
                _ = self
                    .check_intel()
                    .await
                    .map_err(|e| error!(self.id, "intel check error: {:?}", e));
            }
            if self.vulns.is_some() {
                debug!("querying vulnerability check plugins");
                // dont fail alarm update if there's intel check err
                _ = self
                    .check_vuln()
                    .await
                    .map_err(|e| error!("vuln check error: {:?}", e));
            }
        }

        let s = serde_json::to_string(&self)? + "\n";

        if let Some(sender) = &self.log_tx {
            sender.send(LogWriterMessage {
                data: s,
                file_type: FileType::Alarm,
            })?
        }
        Ok(())
    }

    async fn check_intel(&self) -> Result<()> {
        let intels = self
            .intels
            .as_ref()
            .ok_or_else(|| anyhow!("intels is none"))?;
        let mut targets = HashSet::new();
        for s in [&self.src_ips, &self.dst_ips] {
            let r = s.lock();
            targets.extend(r.clone());
        }
        let res = intels.run_checkers(self.intel_private_ip, targets).await?;
        let mut w = self.intel_hits.lock();
        if res == *w {
            debug!("no new intel match found");
            return Ok(());
        }
        let difference = res.difference(&w);
        debug!("found {} new intel matches", difference.count());
        *w = res;
        Ok(())
    }

    async fn check_vuln(&self) -> Result<()> {
        let vulns = self
            .vulns
            .as_ref()
            .ok_or_else(|| anyhow!("vulns is none"))?;

        let mut vs = VulnSearchTerm::default();
        for r in self.rules.iter() {
            let ips: HashSet<&str> = r.from.split(',').collect();
            let ports: HashSet<&str> = r.port_from.split(',').collect();
            let port = self.last_srcport.load(Relaxed);
            vs.add(ips, ports, port);
            let ips: HashSet<&str> = r.to.split(',').collect();
            let ports: HashSet<&str> = r.port_to.split(',').collect();
            let port = self.last_dstport.load(Relaxed);
            vs.add(ips, ports, port);
        }

        let mut combined: HashSet<VulnResult> = HashSet::new();
        for term in vs.terms {
            let ip = term.0;
            let port = term.1;
            debug!("vulnerability check for {}:{}", ip, port);
            let s = ip.to_string() + ":" + &port.to_string();
            {
                let r = self.vulnerabilities.lock();
                let found = r.iter().filter(|v| v.term == s).last();
                if found.is_some() {
                    continue;
                }
            }
            let res = vulns.run_checkers(ip, port).await?;
            combined.extend(res);
        }

        let mut w = self.vulnerabilities.lock();
        if combined == *w {
            debug!("no new vulnerability match found");
            return Ok(());
        }
        let difference = combined.difference(&w);
        debug!("found {} new vulnerability matches", difference.count());
        *w = combined;
        Ok(())
    }
}

#[derive(Default, Debug)]
struct VulnSearchTerm {
    terms: HashSet<(IpAddr, u16)>,
}

impl VulnSearchTerm {
    fn add(&mut self, ip_set: HashSet<&str>, ports: HashSet<&str>, evt_port: u16) {
        for z in ip_set {
            if let Ok(ip) = z.parse::<IpAddr>() {
                if evt_port != 0 {
                    self.terms.insert((ip, evt_port));
                }
                for y in ports.clone() {
                    if let Ok(port) = y.parse::<u16>() {
                        if port != 0 {
                            self.terms.insert((ip, port));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::thread;

    use crate::{directive, log_writer::LogWriter, rule::StickyDiffData};

    use super::*;
    use chrono::Days;
    use tokio::{
        sync::{broadcast, mpsc},
        task,
        time::sleep,
    };
    use tracing_test::traced_test;

    #[test]
    fn test_vuln_searchterm() {
        let mut vs = VulnSearchTerm::default();
        let mut ipset = HashSet::new();
        ipset.insert("192.168.0.1");
        let mut ports = HashSet::new();
        ports.insert("80");
        let evt_port = 443;
        vs.add(ipset.clone(), ports.clone(), evt_port);
        assert!(vs.terms.len() == 2);
        vs.add(ipset, ports, evt_port);
        assert!(vs.terms.len() == 2);
    }

    #[test]
    fn test_saved_reload() {
        let directives = directive::load_directives(
            true,
            Some(vec!["directives".to_string(), "directive5".to_string()]),
        )
        .unwrap();
        let d = directives[0].clone();
        let evt = NormalizedEvent {
            plugin_id: 1337,
            plugin_sid: 1,
            id: "1".to_string(),
            src_ip: "192.168.0.1".parse().unwrap(),
            dst_ip: "10.0.0.131".parse().unwrap(),
            ..Default::default()
        };
        let get_opt = || {
            let asset =
                Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
            let intels = Arc::new(
                crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap(),
            );
            let vulns = Arc::new(
                crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap(),
            );
            let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
            let (bp_tx, _) = mpsc::channel::<()>(1);
            let (log_tx, _) = crossbeam_channel::bounded(1);

            BacklogOpt {
                directive: &d,
                asset,
                intels,
                vulns,
                event: Some(&evt),
                bp_tx,
                delete_tx: mgr_delete_tx,
                min_alarm_lifetime: 0,
                default_status: "Open",
                default_tag: "Identified Threat",
                med_risk_min: 3,
                med_risk_max: 6,
                intel_private_ip: true,
                log_tx,
            }
        };

        let mut event_ids = HashSet::new();
        event_ids.insert("bar".to_string());

        let mut stickydiff_data = StickyDiffData::default();
        stickydiff_data.sdiff_int.push(10);
        stickydiff_data.sdiff_string.push("foo".to_string());

        let last_srcport = 31337;
        let last_dstport = 80;

        let mut b = Backlog::new(&get_opt()).unwrap();
        {
            b.last_srcport.swap(last_srcport, Relaxed);
            b.last_dstport.swap(last_dstport, Relaxed);
            for rule in b.rules.iter_mut() {
                let mut w = rule.sticky_diffdata.lock();
                *w = stickydiff_data.clone();
                let mut w = rule.event_ids.lock();
                *w = event_ids.clone();
            }
        }

        // saveable test
        let saveable = Backlog::saveable_version(Arc::new(b));
        assert_eq!(saveable.saved_last_dstport, Some(last_dstport));
        assert_eq!(saveable.saved_last_srcport, Some(last_srcport));
        for rule in saveable.rules.iter() {
            assert_eq!(rule.saved_event_ids, Some(event_ids.clone()));
            assert_eq!(rule.saved_sticky_diffdata, Some(stickydiff_data.clone()));
        }

        // runable test, reverses saveable
        let runnable = Backlog::runnable_version(get_opt(), saveable).unwrap();
        assert_eq!(runnable.last_srcport.load(Relaxed), last_srcport);
        assert_eq!(runnable.last_dstport.load(Relaxed), last_dstport);
        for rule in runnable.rules.iter() {
            assert_eq!(*rule.event_ids.lock(), event_ids);
            assert_eq!(*rule.sticky_diffdata.lock(), stickydiff_data);
        }

        // should throw error if the saved backlog and the directive have the same ID but different title
        let b = Backlog::new(&get_opt()).unwrap();
        let mut saveable = Backlog::saveable_version(Arc::new(b));
        saveable.title = "foo".to_string();
        let res = Backlog::runnable_version(get_opt(), saveable);
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("different title detected"));

        // should throw error if all rules in the saved backlog already have a status (i.e. finished or timeout)
        let b = Backlog::new(&get_opt()).unwrap();
        let mut saveable = Backlog::saveable_version(Arc::new(b));
        for rule in saveable.rules.iter_mut() {
            rule.status = Arc::new(Mutex::new("finished".to_string()));
        }
        let res = Backlog::runnable_version(get_opt(), saveable);
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("skipping this backlog"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_backlog() {
        let directives = directive::load_directives(
            true,
            Some(vec!["directives".to_string(), "directive5".to_string()]),
        )
        .unwrap();
        let d = directives[0].clone();
        let asset = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let intels =
            Arc::new(crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap());
        let vulns =
            Arc::new(crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap());
        let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
        let (event_tx, event_rx) = broadcast::channel(10);
        let (bp_tx, _) = mpsc::channel::<()>(1);
        let (resptime_tx, _resptime_rx) = mpsc::channel::<f64>(128);

        let mut log_writer = LogWriter::new(true).unwrap();
        let log_tx = log_writer.sender.clone();

        let _ = thread::spawn(move || {
            log_writer.listener().unwrap();
        });

        let now = Utc::now().timestamp_nanos_opt().unwrap();

        let mut evt = NormalizedEvent {
            plugin_id: 1337,
            plugin_sid: 1,
            id: "1".to_string(),
            src_ip: "192.168.0.1".parse().unwrap(),
            dst_ip: "192.168.0.2".parse().unwrap(),
            src_port: 31337,
            dst_port: 80,
            custom_label1: "label".to_string(),
            custom_data1: "data".to_string(),
            custom_label2: "label".to_string(),
            custom_data2: "data".to_string(),
            custom_label3: "label".to_string(),
            custom_data3: "data".to_string(),
            rcvd_time: now - 10000,
            ..Default::default()
        };

        let evt_cloned = evt.clone();
        let opt = BacklogOpt {
            directive: &d,
            asset: asset.clone(),
            intels,
            vulns,
            event: Some(&evt_cloned),
            bp_tx,
            delete_tx: mgr_delete_tx,
            default_status: "Open",
            default_tag: "Identified Threat",
            min_alarm_lifetime: 0,
            med_risk_min: 3,
            med_risk_max: 6,
            intel_private_ip: true,
            log_tx,
        };
        let backlog = Backlog::new(&opt).unwrap();
        trace!(backlog.id, "backlog: {:?}", backlog);

        // make sure SRC_IP and DST_IP replacement works
        let src_host = asset.clone().get_name(&evt.src_ip).unwrap();
        let dst_host = asset.clone().get_name(&evt.dst_ip).unwrap();
        assert!(backlog.title.contains(&src_host));
        assert!(backlog.title.contains(&dst_host));

        let arc_backlog = Arc::new(backlog);
        let cloned = arc_backlog.clone();

        let _detached = task::spawn(async move {
            _ = cloned
                .start(event_rx, Some(evt_cloned), resptime_tx, 1)
                .await;
        });

        // these matching event should increase level from 2 to 3 to 4, and raise risk
        evt.id = "2".to_string();
        evt.src_ip = "0.0.0.0".parse().unwrap();
        evt.dst_ip = "0.0.0.0".parse().unwrap();
        event_tx.send(evt.clone()).unwrap();

        evt.id = "3".to_string();
        evt.dst_ip = "192.168.0.2".parse().unwrap();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("risk changed"));
        assert!(logs_contain("stage increased to 4"));

        // make sure created_time is set
        let created_time = arc_backlog.created_time.load(Relaxed);
        assert!(created_time != 0);

        // event with out of order timestamp
        sleep(Duration::from_millis(500)).await;
        evt.timestamp = Utc::now().checked_sub_days(Days::new(1)).unwrap();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(3000)).await;
        assert!(logs_contain("discarded out of order event"));

        // these matching event should reach max occurrence for stage 4
        evt.timestamp = Utc::now();
        evt.id = "4".to_string();
        event_tx.send(evt.clone()).unwrap();
        evt.id = "5".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("reached max stage and occurrence"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_all_rules_always_active_n_stickydiff() {
        let directives = directive::load_directives(
            true,
            Some(vec!["directives".to_string(), "directive6".to_string()]),
        )
        .unwrap();
        let d = directives[0].clone();
        let asset = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());

        let mut intel_plugin =
            crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap();
        intel_plugin.checkers = Arc::new(vec![]); // disable, we're not testing this
        let intels = Arc::new(intel_plugin);

        let mut vuln_plugin =
            crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap();
        vuln_plugin.checkers = Arc::new(vec![]); // disable, we're not testing this
        let vulns = Arc::new(vuln_plugin);

        let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
        let (event_tx, event_rx) = broadcast::channel(10);
        let (bp_tx, _) = mpsc::channel::<()>(1);
        let (resptime_tx, _resptime_rx) = mpsc::channel::<f64>(128);

        let mut log_writer = LogWriter::new(true).unwrap();
        let log_tx = log_writer.sender.clone();
        let _ = thread::spawn(move || {
            log_writer.listener().unwrap();
        });

        let mut evt = NormalizedEvent {
            plugin_id: 1337,
            plugin_sid: 1,
            id: "1".to_string(),
            src_ip: "192.168.0.1".parse().unwrap(),
            dst_ip: "10.0.0.131".parse().unwrap(),
            src_port: 31337,
            dst_port: 80,
            ..Default::default()
        };

        let evt_cloned = evt.clone();
        let opt = BacklogOpt {
            directive: &d,
            asset,
            intels,
            vulns,
            event: Some(&evt_cloned),
            bp_tx,
            delete_tx: mgr_delete_tx,
            default_status: "Open",
            default_tag: "Identified Threat",
            min_alarm_lifetime: 0,
            med_risk_min: 3,
            med_risk_max: 5,
            intel_private_ip: true,
            log_tx,
        };
        let backlog = Backlog::new(&opt).unwrap();
        let _detached = task::spawn(async move {
            _ = backlog
                .start(event_rx, Some(evt_cloned), resptime_tx, 1)
                .await;
        });

        evt.id = "2".to_string();
        evt.src_port = 31313;
        event_tx.send(evt.clone()).unwrap();
        evt.id = "3".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("previous rule consume event"));

        // these shouldn't match
        evt.id = "4".to_string();
        evt.plugin_sid = 3;
        event_tx.send(evt.clone()).unwrap();
        evt.id = "5".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("event doesn't match"));
        // these matching event should be captured by first rule, but only when there's uniq SRC_PORT (sticky_different)

        // this should increase risk to 1 (Low)
        evt.plugin_sid = 2;
        evt.src_port = 31337;
        evt.id = "6".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;

        evt.id = "7".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain(
            "backlog can't find new unique value in stickydiff field"
        ));

        evt.src_port = 31313;
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("risk changed from 0 to 1"));

        // this should increase risk to 6 (High, because med_risk_max = 5 )
        evt.plugin_sid = 3;
        evt.id = "8".to_string();
        event_tx.send(evt.clone()).unwrap();
        evt.id = "9".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(2000)).await;
        assert!(logs_contain("risk changed from 1 to 6"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_expired() {
        let directives = directive::load_directives(
            true,
            Some(vec!["directives".to_string(), "directive5".to_string()]),
        )
        .unwrap();
        let d = directives[0].clone();
        let asset = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let intels =
            Arc::new(crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap());
        let vulns =
            Arc::new(crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap());
        let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
        let (_, event_rx) = broadcast::channel(10);
        let (bp_tx, _bp_rx) = mpsc::channel::<()>(8);
        let (resptime_tx, _resptime_rx) = mpsc::channel::<f64>(128);

        info!("about to start blocking");
        let mut log_writer = LogWriter::new(true).unwrap();
        let log_tx = log_writer.sender.clone();
        let _ = thread::spawn(move || {
            log_writer.listener().unwrap();
        });

        info!("done spawn blocking");

        let evt = NormalizedEvent {
            plugin_id: 1337,
            plugin_sid: 1,
            custom_label1: "label".to_string(),
            custom_data1: "data".to_string(),
            ..Default::default()
        };

        let _detached = task::spawn(async move {
            let opt = BacklogOpt {
                directive: &d,
                asset,
                intels,
                vulns,
                event: Some(&evt),
                bp_tx,
                delete_tx: mgr_delete_tx,
                default_status: "Open",
                default_tag: "Identified Threat",
                min_alarm_lifetime: 0,
                med_risk_min: 3,
                med_risk_max: 6,
                intel_private_ip: false,
                log_tx,
            };
            let backlog = Backlog::new(&opt).unwrap();
            _ = backlog.start(event_rx, Some(evt), resptime_tx, 0).await;
        });

        // expired
        sleep(Duration::from_millis(13000)).await;
        assert!(logs_contain("backlog expired"));
    }
}
