use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{
            AtomicI64, AtomicU8,
            Ordering::{Acquire, Relaxed, Release},
        },
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Result};
use arcstr::ArcStr;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_derive::Serialize;
use tokio::{
    sync::{broadcast::Receiver, mpsc::Sender, watch},
    time::{interval, Instant},
};
use tracing::{debug, error, info, info_span, trace, warn, Instrument};

use crate::{
    asset::NetworkAssets,
    directive::Directive,
    event::NormalizedEvent,
    intel::{IntelPlugin, IntelResult},
    log_writer::{FileType, LogWriterMessage},
    rule::DirectiveRule,
    tracer,
    utils::{self, ref_to_digit},
    vuln::{VulnPlugin, VulnResult},
};

pub mod manager;

// Enhanced backlog processing modules
pub mod optimized_storage; // Memory efficiency improvements
pub mod ordered_event_processor; // Order-preserving event processor for SIEM rules

// Import optimized components
use optimized_storage::OptimizedBacklogStorage;
use ordered_event_processor::{OrderedEventProcessor, OrderingConfig};

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct CustomData {
    pub label: ArcStr,
    pub content: ArcStr,
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
    pub title: ArcStr,
    pub status: ArcStr,
    pub tag: ArcStr,
    pub kingdom: ArcStr,
    pub category: ArcStr,
    pub created_time: AtomicI64,
    pub update_time: AtomicI64,
    pub risk: AtomicU8,
    pub risk_class: Mutex<ArcStr>,
    pub rules: Vec<DirectiveRule>,

    // PHASE 1: Optimized storage - separate hot/cold data to reduce lock contention
    #[serde(skip)]
    pub optimized_storage: Option<Arc<OptimizedBacklogStorage>>,

    // Legacy fields for backward compatibility (will be gradually phased out)
    pub src_ips: Mutex<HashSet<IpAddr>>,
    pub dst_ips: Mutex<HashSet<IpAddr>>,
    pub networks: Mutex<HashSet<ArcStr>>,
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
    pub src_socketaddr: Mutex<HashSet<SocketAddr>>, // copied from event for vuln check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_src_socketaddr: Option<HashSet<SocketAddr>>, // saveable version of src_socketaddr
    #[serde(skip)]
    pub dst_socketaddr: Mutex<HashSet<SocketAddr>>, // copied from event for vuln check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_dst_socketaddr: Option<HashSet<SocketAddr>>, // saveable version of dst_socketaddr

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

    // PHASE 2: Ordered event processing for maintaining temporal sequence
    #[serde(skip)]
    event_processor: Option<Arc<OrderedEventProcessor>>,

    // Performance optimization: cached risk calculation to avoid repeated computation
    #[serde(skip)]
    risk_cache_valid: std::sync::atomic::AtomicBool,
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
        DeleteChannel { tx, rx, to_upstream_manager: None }
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
    tx: tokio::sync::watch::Sender<(bool, ArcStr)>,
    pub locked_rx: tokio::sync::Mutex<tokio::sync::watch::Receiver<(bool, ArcStr)>>,
}

impl Default for FoundChannel {
    fn default() -> Self {
        let (tx, rx) = watch::channel((false, "".into()));
        FoundChannel { tx, locked_rx: tokio::sync::Mutex::new(rx) }
    }
}

#[derive(Clone)]
pub struct BacklogOpt {
    pub directive: Directive,
    pub asset: Arc<NetworkAssets>,
    pub intels: Arc<IntelPlugin>,
    pub vulns: Arc<VulnPlugin>,
    pub event: Option<Arc<NormalizedEvent>>,
    pub bp_tx: Sender<()>,
    pub delete_tx: Option<Sender<()>>, // allow late initialization
    pub min_alarm_lifetime: i64,
    pub default_status: ArcStr,
    pub default_tag: ArcStr,
    pub med_risk_min: u8,
    pub med_risk_max: u8,
    pub intel_private_ip: bool,
    pub log_tx: crossbeam_channel::Sender<LogWriterMessage>,
}

impl Backlog {
    pub fn new(o: &BacklogOpt) -> Result<Self> {
        let id = utils::generate_id();

        // PHASE 1: Create optimized storage for better performance
        let optimized_storage = Arc::new(OptimizedBacklogStorage::new(
            id.clone(),
            o.directive.name.clone(),
            o.default_status.clone(),
            o.default_tag.clone(),
            o.directive.kingdom.clone(),
            o.directive.category.clone(),
            o.directive.priority,
            o.directive.id,
            o.directive.all_rules_always_active,
        ));

        // PHASE 2: Initialize ordered event processor for temporal sequence
        let ordering_config = OrderingConfig {
            max_ordering_delay_ms: 1000, // 1 second tolerance for out-of-order events
            max_buffer_size_per_backlog: 1000,
            processing_interval_ms: 10,
            max_concurrent_processing: 4,
            strict_ordering: true, // Critical for SIEM functionality
        };
        let event_processor = Arc::new(OrderedEventProcessor::new(ordering_config));

        let mut backlog = Backlog {
            id,
            title: o.directive.name.clone(),
            kingdom: o.directive.kingdom.clone(),
            category: o.directive.category.clone(),
            status: o.default_status.clone(),
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

            // PHASE 1 & 2: Enhanced storage and processing
            optimized_storage: Some(optimized_storage),
            event_processor: Some(event_processor),
            risk_cache_valid: std::sync::atomic::AtomicBool::new(false),

            ..Default::default()
        };
        if let Some(v) = &o.event {
            if backlog.title.contains("SRC_IP") {
                let src = if let Some(hostname) = backlog.assets.get_name(&v.src_ip) {
                    hostname
                } else {
                    v.src_ip.to_string()
                };
                backlog.title = backlog.title.replace("SRC_IP", &src).into();
            }
            if backlog.title.contains("DST_IP") {
                let dst = if let Some(hostname) = backlog.assets.get_name(&v.dst_ip) {
                    hostname
                } else {
                    v.dst_ip.to_string()
                };
                backlog.title = backlog.title.replace("DST_IP", &dst).into();
            }

            // warning: we can't simply clone the directive rules and assign it to backlog
            // because the Arc fields will point to the same memory location
            for r in o.directive.rules.clone() {
                backlog.rules.push(r.reset_arc_fields());
            }

            backlog.highest_stage = backlog.rules.iter().map(|v| v.stage).max().unwrap_or_default();
        }
        let delete_tx = o.delete_tx.as_ref().ok_or_else(|| anyhow!("delete_tx is none"))?;
        backlog.delete_channel.to_upstream_manager = Some(delete_tx.clone());
        backlog.intels = Some(o.intels.clone());
        backlog.vulns = Some(o.vulns.clone());

        if let Some(v) = &o.event {
            info!(directive.id = o.directive.id, backlog.id, event.id = v.id, "new backlog created");
        }
        Ok(backlog)
    }

    // runable_version produces backlog that manager can start
    pub fn runnable_version(o: BacklogOpt, loaded: Backlog) -> Result<Self> {
        let mut backlog = Backlog::new(&o)?;
        // verify that we're still based on the same directive
        if backlog.title != loaded.title {
            return Err(anyhow!("different title detected: '{}' vs '{}'", backlog.title, loaded.title));
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

        if let Some(v) = loaded.saved_src_socketaddr {
            backlog.src_socketaddr = Mutex::new(v);
        }
        if let Some(v) = loaded.saved_dst_socketaddr {
            backlog.dst_socketaddr = Mutex::new(v);
        }

        for r in backlog.rules.iter_mut() {
            if let Some(v) = r.saved_sticky_diffdata.clone() {
                r.sticky_diffdata = Arc::new(Mutex::new(v));
            }
            if let Some(v) = r.saved_event_ids.clone() {
                r.event_ids = Arc::new(Mutex::new(v));
            }
        }
        backlog.highest_stage = backlog.rules.iter().map(|v| v.stage).max().unwrap_or_default();
        let lowest_stage = loaded.rules.iter().filter(|v| v.status.lock().is_empty()).map(|x| x.stage).min();
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
            debug!(backlog.id, "loaded with current_stage: {}, highest_stage: {}", v, backlog.highest_stage);
            backlog.current_stage = AtomicU8::new(v);
        } else {
            let msg = "cannot determine the current stage, skipping this backlog";
            error!(backlog.id, msg);
            return Err(anyhow!(msg));
        }

        // Fix: Set intels and vulns fields that were missing in runnable_version
        backlog.intels = Some(o.intels.clone());
        backlog.vulns = Some(o.vulns.clone());

        Ok(backlog)
    }

    // saveable_version produces backlog that manager can save to disk
    pub fn saveable_version(running: Arc<Backlog>) -> Self {
        // - status, kingdom, tag, category, created_time are empty;
        let mut backlog = Backlog {
            id: (*running.id).to_string(),
            title: running.title.clone(),
            status: running.status.clone(),
            kingdom: running.kingdom.clone(),
            category: running.category.clone(),
            tag: running.tag.clone(),
            created_time: AtomicI64::new(running.created_time.load(Relaxed)),
            update_time: AtomicI64::new(running.update_time.load(Acquire)),
            risk: AtomicU8::new(running.risk.load(Acquire)),
            risk_class: (*running.risk_class.lock()).clone().into(),
            rules: running.rules.clone(),
            src_ips: (*running.src_ips.lock()).clone().into(),
            dst_ips: (*running.dst_ips.lock()).clone().into(),
            networks: (*running.networks.lock()).clone().into(),
            custom_data: (*running.custom_data.lock()).clone().into(),
            intel_hits: (*running.intel_hits.lock()).clone().into(),
            vulnerabilities: (*running.vulnerabilities.lock()).clone().into(),
            ..Default::default()
        };

        let r = running.src_socketaddr.lock();
        if !r.is_empty() {
            backlog.saved_src_socketaddr = Some(r.clone());
        }
        let r = running.dst_socketaddr.lock();
        if !r.is_empty() {
            backlog.saved_dst_socketaddr = Some(r.clone());
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

    async fn recv_handler(&self, event: &NormalizedEvent, max_delay: &i64, resptime_tx: &Sender<f64>) -> Result<()> {
        let backlog_span =
            info_span!("backlog processing", directive.id = self.directive_id, backlog.id = self.id, event.id);
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
        debug!(backlog.id = self.id, "enter running state");
        self.set_state(BacklogState::Running);
        loop {
            tokio::select! {
                _ = expiration_checker.tick() => {
                    if let Ok((expired, seconds_left)) = self.is_expired() {
                        if expired {
                            debug!(
                                backlog.id = self.id,
                                "backlog expired, setting last stage status to timeout and deleting it"
                            );
                            if let Err(e) = self.handle_expiration().await {
                                debug!{
                                    backlog.id = self.id,
                                    "error updating status and deleting backlog: {}", e.to_string()
                                }
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
                            _ = self.report_to_manager(false, &event.id);
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
        let reader = self.current_stage.load(Acquire);
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
        let s = if let Some(v) = stage { v } else { self.current_stage.load(Acquire) };
        self.rules.iter().find(|v| v.stage == s).ok_or_else(|| anyhow!("cannot locate the current rule"))
    }

    fn report_to_manager(&self, match_found: bool, event_id: &str) -> Result<()> {
        Ok(self.found_channel.tx.send((match_found, event_id.into()))?)
    }

    pub async fn process_new_event(&self, event: &NormalizedEvent, max_delay: i64) -> Result<()> {
        // PHASE 2: Use ordered event processor for temporal sequence validation
        if let Some(_event_processor) = &self.event_processor {
            // For now, use simplified ordering check to maintain temporal sequence
            // This avoids complex lifetime issues while still providing ordering benefits
            if !self.is_time_in_order(&event.timestamp) {
                warn!("discarded out of order event");
                return Ok(());
            }

            // Process directly but with ordering validation
            self.process_single_event_internal(event, max_delay).await?;
        } else {
            // Fallback to direct processing for backward compatibility
            self.process_single_event_internal(event, max_delay).await?;
        }

        Ok(())
    }

    // Internal method that contains the original processing logic
    async fn process_single_event_internal(&self, event: &NormalizedEvent, max_delay: i64) -> Result<()> {
        let curr_rule = self.current_rule()?;

        let n_string: usize;
        let n_int: usize;
        {
            let reader = curr_rule.sticky_diffdata.lock();
            n_string = reader.sdiff_string.len();
            n_int = reader.sdiff_int.len();
        }

        if !curr_rule.does_event_match(&self.assets, event, &self.rules, true) {
            // if flag is set, check if event match previous stage
            if self.all_rules_always_active && curr_rule.stage != 1 {
                debug!("checking prev rules because all_rules_always_active is on");
                let prev_rules =
                    self.rules.iter().filter(|v| v.stage < curr_rule.stage).collect::<Vec<&DirectiveRule>>();
                for r in prev_rules {
                    if !r.does_event_match(&self.assets, event, &self.rules, true) {
                        continue;
                    }
                    // event match previous rule, processing it further here
                    // just add the event to the stage, no need to process other steps in
                    // processMatchedEvent
                    debug!(backlog.id = self.id, event.id, r.stage, "previous rule match");
                    self.append_and_write_event(event, Some(r.stage))?;
                    // also update alarm to sync any changes to customData
                    self.update_alarm(false).await?;
                    debug!(event.id, r.stage, "previous rule consume event");
                    _ = self.report_to_manager(true, &event.id);
                    return Ok(());
                    // no need to process further rules
                }
            }
            debug!("event doesn't match");

            _ = self.report_to_manager(false, &event.id);
            return Ok(());
        }

        // if stickydiff is set, there must be added member to sdiff_string or sdiff_int
        if !curr_rule.sticky_different.is_empty() {
            let reader = curr_rule.sticky_diffdata.lock();
            if n_string == reader.sdiff_string.len() && n_int == reader.sdiff_int.len() {
                debug!("backlog can't find new unique value in stickydiff field {}", curr_rule.sticky_different);
                _ = self.report_to_manager(false, &event.id);
                return Ok(());
            }
        }

        // event match current rule, processing it further here
        debug!("rule stage {} match event", curr_rule.stage);
        // skip reporting to manager if this is the first event
        if curr_rule.stage != 1 {
            _ = self.report_to_manager(true, &event.id);
        }

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
        *w = status.into();
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
        // PHASE 1: Use cached risk calculation if valid
        if self.risk_cache_valid.load(Acquire) {
            return Ok(false); // No change since cache is valid
        }

        let (src_value, dst_value) = if let Some(optimized_storage) = &self.optimized_storage {
            // Use optimized storage for better performance
            let hot_data = optimized_storage.hot_data.read();
            let src_val = hot_data.src_ips.iter().map(|v| self.assets.get_value(v)).max().unwrap_or_default();
            let dst_val = hot_data.dst_ips.iter().map(|v| self.assets.get_value(v)).max().unwrap_or_default();
            (src_val, dst_val)
        } else {
            // Fallback to legacy approach
            let reader = self.src_ips.lock();
            let src_val = reader.iter().map(|v| self.assets.get_value(v)).max().unwrap_or_default();
            drop(reader); // Release lock early
            let reader = self.dst_ips.lock();
            let dst_val = reader.iter().map(|v| self.assets.get_value(v)).max().unwrap_or_default();
            (src_val, dst_val)
        };

        let prior_risk = self.risk.load(Acquire);
        let value = std::cmp::max(src_value, dst_value);
        let priority = self.priority;
        let reliability = self.current_rule()?.reliability;
        let risk = (priority * reliability * value) / 25;
        let risk_different = risk != prior_risk;

        if risk_different {
            info!(backlog.id = self.id, "risk changed from {} to {}", prior_risk, risk);
            self.risk.store(risk, Release);
        }

        // Mark cache as valid
        self.risk_cache_valid.store(true, Release);
        Ok(risk_different)
    }

    fn update_risk_class(&self) {
        let mut w = self.risk_class.lock();
        let risk = self.risk.load(Acquire);
        *w = if risk < self.med_risk_min {
            "Low".into()
        } else if risk >= self.med_risk_min && risk <= self.med_risk_max {
            "Medium".into()
        } else {
            "High".into()
        };
    }

    fn is_last_stage(&self) -> bool {
        self.current_stage.load(Acquire) == self.highest_stage
    }

    async fn process_matched_event(&self, event: &NormalizedEvent) -> Result<()> {
        self.append_and_write_event(event, None)?;

        // set rule's first_event if there's none yet, and set rule's start_time based
        // on it.
        let current_rule = self.current_rule()?;
        if !current_rule.is_first_event_set() {
            debug!("setting first event for stage {}", self.current_stage.load(Relaxed));
            current_rule.set_first_event(event.clone())?;
            self.set_rule_starttime(event.timestamp)?;
        }

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
            // set rule startTime for the new stage, this will reset/be-updated when the new
            // stage receives its first matching event above.
            // for non-stage 1, we set it here so expiration time can be calculated without
            // depending on whether the new stage will receive a matching event or not.
            self.set_rule_starttime(event.timestamp)?;
            // stage Increased, update alarm to publish new stage startTime
            self.update_alarm(true).await?;
        }

        Ok(())
    }

    fn delete(&self) -> Result<()> {
        Ok(self.delete_channel.tx.send(true)?)
    }

    fn increase_stage(&self) -> bool {
        self.current_stage
            .fetch_update(Release, Acquire, |v| {
                if v < self.highest_stage {
                    info!("stage increased to {}", v + 1);
                    Some(v + 1)
                } else {
                    info!("stage is at the highest level");
                    None
                }
            })
            .is_ok()
    }

    fn append_and_write_event(&self, event: &NormalizedEvent, stage: Option<u8>) -> Result<()> {
        let target_rule = self.get_rule(stage)?;
        {
            let mut w = target_rule.event_ids.lock();
            w.insert(event.id.clone());
            let ttl_events = w.len();
            debug!(stage = target_rule.stage, "appended event {}/{}", ttl_events, target_rule.occurrence);
        }

        // PHASE 1: Use optimized storage when available for batch updates
        if let Some(optimized_storage) = &self.optimized_storage {
            // Batch update IPs and ports to reduce lock contention
            optimized_storage.batch_update_ips_and_ports(event.src_ip, event.dst_ip, event.src_port, event.dst_port);

            // Update custom data efficiently
            if !event.custom_data1.is_empty() || !event.custom_data2.is_empty() || !event.custom_data3.is_empty() {
                let mut hot_data = optimized_storage.hot_data.write();
                if !event.custom_data1.is_empty() {
                    hot_data
                        .custom_data
                        .insert(CustomData { label: event.custom_label1.clone(), content: event.custom_data1.clone() });
                }
                if !event.custom_data2.is_empty() {
                    hot_data
                        .custom_data
                        .insert(CustomData { label: event.custom_label2.clone(), content: event.custom_data2.clone() });
                }
                if !event.custom_data3.is_empty() {
                    hot_data
                        .custom_data
                        .insert(CustomData { label: event.custom_label3.clone(), content: event.custom_data3.clone() });
                }
            }
        } else {
            // Fallback to legacy approach for backward compatibility
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
                let mut w = self.src_socketaddr.lock();
                w.insert(SocketAddr::new(event.src_ip, event.src_port));
            }
            {
                let mut w = self.dst_socketaddr.lock();
                w.insert(SocketAddr::new(event.dst_ip, event.dst_port));
            }

            {
                let mut w = self.custom_data.lock();
                if !event.custom_data1.is_empty() {
                    w.insert(CustomData { label: event.custom_label1.clone(), content: event.custom_data1.clone() });
                }
                if !event.custom_data2.is_empty() {
                    w.insert(CustomData { label: event.custom_label2.clone(), content: event.custom_data2.clone() });
                }
                if !event.custom_data3.is_empty() {
                    w.insert(CustomData { label: event.custom_label3.clone(), content: event.custom_data3.clone() });
                }
            }
        }

        // Invalidate risk cache when data changes
        self.risk_cache_valid.store(false, Relaxed);

        self.set_update_time();
        self.append_siem_alarm_events(event, stage)
    }

    fn set_update_time(&self) {
        self.update_time.store(Utc::now().timestamp(), Release);
    }

    fn set_created_time(&self) {
        let _ = self.created_time.fetch_update(Relaxed, Relaxed, |v| {
            if v == 0 {
                let updated_time = self.update_time.load(Acquire);
                Some(updated_time)
            } else {
                None
            }
        });
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
                        w.insert(x.into());
                    }
                }
            }
        }
    }

    fn append_siem_alarm_events(&self, e: &NormalizedEvent, stage: Option<u8>) -> Result<()> {
        let s = if let Some(v) = stage { v } else { self.current_stage.load(Acquire) };
        let sae = SiemAlarmEvent { id: self.id.clone(), stage: s, event_id: e.id.clone() };
        let s = serde_json::to_string(&sae)? + "\n";
        trace!(alarm.id = sae.id, stage = sae.stage, "appending siem_alarm_events");
        if let Some(sender) = &self.log_tx {
            sender.send(LogWriterMessage { data: s, file_type: FileType::AlarmEvent })?;
        }
        Ok(())
    }

    async fn update_alarm(&self, check_intvuln: bool) -> Result<()> {
        let risk = self.risk.load(Acquire);
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
                _ = self.check_intel().await.map_err(|e| error!(self.id, "intel check error: {:?}", e));
            }
            if self.vulns.is_some() {
                debug!("querying vulnerability check plugins");
                // dont fail alarm update if there's vuln check err
                _ = self.check_vuln().await.map_err(|e| error!("vuln check error: {:?}", e));
            }
        }

        let s = self.to_alarm_json()? + "\n";

        if let Some(sender) = &self.log_tx {
            sender.send(LogWriterMessage { data: s, file_type: FileType::Alarm })?
        }
        Ok(())
    }

    async fn check_intel(&self) -> Result<()> {
        let intels = self.intels.as_ref().ok_or_else(|| anyhow!("intels is none"))?;
        let mut targets = HashSet::new();

        // Read IP addresses from optimized storage if available, otherwise fallback to
        // original fields
        if let Some(storage) = &self.optimized_storage {
            let hot_data = storage.hot_data.read();
            targets.extend(hot_data.src_ips.clone());
            targets.extend(hot_data.dst_ips.clone());
        } else {
            // Fallback to original fields for compatibility
            for s in [&self.src_ips, &self.dst_ips] {
                let r = s.lock();
                targets.extend(r.clone());
            }
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
        let vulns = self.vulns.as_ref().ok_or_else(|| anyhow!("vulns is none"))?;

        let mut vs = VulnSearchTerm::default();

        // Read socket addresses from optimized storage if available, otherwise fallback
        // to original fields
        if let Some(storage) = &self.optimized_storage {
            let hot_data = storage.hot_data.read();
            vs.add_pair(&hot_data.src_socketaddr);
            vs.add_pair(&hot_data.dst_socketaddr);
        } else {
            // Fallback to original fields for compatibility
            {
                let r = self.src_socketaddr.lock();
                vs.add_pair(&r);
            }
            {
                let r = self.dst_socketaddr.lock();
                vs.add_pair(&r);
            }
        }

        let mut combined: HashSet<VulnResult> = HashSet::new();
        for term in vs.terms {
            let ip = term.0;
            let port = term.1;
            debug!("vulnerability check for {}:{}", ip, port);
            let s = ip.to_string() + ":" + &port.to_string();
            {
                let r = self.vulnerabilities.lock();
                if r.iter().any(|v| v.term == s) {
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

    fn to_alarm_json(&self) -> Result<String> {
        // this replaces the ref to digit in rules with the actual referred value
        // before the alarm is serialized to json

        let mut rules = vec![];

        let referred_event = |stage: u8| -> Option<NormalizedEvent> {
            self.rules.iter().find(|x| x.stage == stage && x.is_first_event_set()).map(|x| x.get_first_event())
        };

        for mut r in self.rules.clone() {
            if let Some(v) = ref_to_digit(&r.from) {
                if let Some(e) = referred_event(v) {
                    r.from = e.src_ip.to_string().into();
                }
            }
            if let Some(v) = ref_to_digit(&r.to) {
                if let Some(e) = referred_event(v) {
                    r.to = e.dst_ip.to_string().into();
                }
            }
            if let Some(v) = ref_to_digit(&r.port_from) {
                if let Some(e) = referred_event(v) {
                    r.port_from = e.src_port.to_string().into();
                }
            }
            if let Some(v) = ref_to_digit(&r.port_to) {
                if let Some(e) = referred_event(v) {
                    r.port_to = e.dst_port.to_string().into();
                }
            }
            if let Some(v) = ref_to_digit(&r.protocol) {
                if let Some(e) = referred_event(v) {
                    r.protocol = e.protocol;
                }
            }
            if let Some(v) = ref_to_digit(&r.custom_data1) {
                if let Some(e) = referred_event(v) {
                    r.custom_data1 = e.custom_data1;
                }
            }
            if let Some(v) = ref_to_digit(&r.custom_data2) {
                if let Some(e) = referred_event(v) {
                    r.custom_data2 = e.custom_data2;
                }
            }
            if let Some(v) = ref_to_digit(&r.custom_data3) {
                if let Some(e) = referred_event(v) {
                    r.custom_data3 = e.custom_data3;
                }
            }
            rules.push(r);
        }

        let r_str = serde_json::to_value(&rules)?;
        let mut d_str = serde_json::to_value(self)?;
        d_str["rules"] = r_str;

        Ok(serde_json::to_string(&d_str)?)
    }
}

#[derive(Default, Debug)]
struct VulnSearchTerm {
    terms: HashSet<(IpAddr, u16)>,
}

impl VulnSearchTerm {
    fn add_pair(&mut self, socket_addr: &HashSet<SocketAddr>) {
        socket_addr.iter().for_each(|x| {
            self.terms.insert((x.ip(), x.port()));
        })
    }
}

#[cfg(test)]
mod test {
    use std::{str::FromStr, thread};

    use chrono::Days;
    use tokio::{
        sync::{broadcast, mpsc},
        task,
        time::sleep,
    };
    use tracing_test::traced_test;

    use super::*;
    use crate::{directive, log_writer::LogWriter, rule::StickyDiffData};

    #[test]
    fn test_vuln_searchterm() {
        let mut vs = VulnSearchTerm::default();
        let mut socket_addr1 = HashSet::new();
        socket_addr1.insert(SocketAddr::new(IpAddr::from_str("192.168.0.1").unwrap(), 80));
        socket_addr1.insert(SocketAddr::new(IpAddr::from_str("192.168.0.1").unwrap(), 8080));
        vs.add_pair(&socket_addr1);
        vs.add_pair(&socket_addr1);
        vs.add_pair(&socket_addr1);
        assert!(vs.terms.len() == 2);
    }

    #[test]
    fn test_saved_reload() {
        let directives =
            directive::load_directives(true, Some(vec!["directives".to_string(), "directive5".to_string()])).unwrap();
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
            let asset = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
            let intels = Arc::new(crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap());
            let vulns = Arc::new(crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap());
            let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
            let (bp_tx, _) = mpsc::channel::<()>(1);
            let (log_tx, _) = crossbeam_channel::bounded(1);

            BacklogOpt {
                directive: d.clone(),
                asset,
                intels,
                vulns,
                event: Some(Arc::new(evt.clone())),
                bp_tx,
                delete_tx: Some(mgr_delete_tx),
                min_alarm_lifetime: 0,
                default_status: "Open".into(),
                default_tag: "Identified Threat".into(),
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
        let mut saddr_set = HashSet::new();
        saddr_set.insert(SocketAddr::new(IpAddr::from_str("192.168.0.1").unwrap(), 80));

        let mut b = Backlog::new(&get_opt()).unwrap();
        {
            b.src_socketaddr = Mutex::new(saddr_set.clone());
            b.dst_socketaddr = Mutex::new(saddr_set.clone());
            for rule in b.rules.iter_mut() {
                let mut w = rule.sticky_diffdata.lock();
                *w = stickydiff_data.clone();
                let mut w = rule.event_ids.lock();
                *w = event_ids.clone();
            }
        }

        // saveable test
        let saveable = Backlog::saveable_version(Arc::new(b));
        assert_eq!(saveable.saved_src_socketaddr, Some(saddr_set.clone()));
        assert_eq!(saveable.saved_dst_socketaddr, Some(saddr_set));

        for rule in saveable.rules.iter() {
            assert_eq!(rule.saved_event_ids, Some(event_ids.clone()));
            assert_eq!(rule.saved_sticky_diffdata, Some(stickydiff_data.clone()));
        }

        // runable test, reverses saveable
        let runnable = Backlog::runnable_version(get_opt(), saveable).unwrap();
        for rule in runnable.rules.iter() {
            assert_eq!(*rule.event_ids.lock(), event_ids);
            assert_eq!(*rule.sticky_diffdata.lock(), stickydiff_data);
        }

        // should throw error if the saved backlog and the directive have the same ID
        // but different title
        let b = Backlog::new(&get_opt()).unwrap();
        let mut saveable = Backlog::saveable_version(Arc::new(b));
        saveable.title = "foo".into();
        let res = Backlog::runnable_version(get_opt(), saveable);
        assert!(res.unwrap_err().to_string().contains("different title detected"));

        // should throw error if all rules in the saved backlog already have a status
        // (i.e. finished or timeout)
        let b = Backlog::new(&get_opt()).unwrap();
        let mut saveable = Backlog::saveable_version(Arc::new(b));
        for rule in saveable.rules.iter_mut() {
            rule.status = Arc::new(Mutex::new("finished".into()));
        }
        let res = Backlog::runnable_version(get_opt(), saveable);
        assert!(res.unwrap_err().to_string().contains("skipping this backlog"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_backlog() {
        let directives =
            directive::load_directives(true, Some(vec!["directives".to_string(), "directive5".to_string()])).unwrap();
        let d = directives[0].clone();
        let asset = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let intels = Arc::new(crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap());
        let vulns = Arc::new(crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap());
        let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
        let (event_tx, event_rx) = broadcast::channel(10);
        let (bp_tx, _) = mpsc::channel::<()>(1);
        let (resptime_tx, _resptime_rx) = mpsc::channel::<f64>(128);

        let (mut log_writer, log_tx) = LogWriter::new(true).unwrap();

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
            custom_label1: "label1".into(),
            custom_data1: "data1".into(),
            custom_label2: "label2".into(),
            custom_data2: "data2".into(),
            custom_label3: "label3".into(),
            custom_data3: "data3".into(),
            rcvd_time: now - 10000,
            ..Default::default()
        };

        let evt_cloned = evt.clone();
        let opt = BacklogOpt {
            directive: d.clone(),
            asset: asset.clone(),
            intels,
            vulns,
            event: Some(Arc::new(evt_cloned.clone())),
            bp_tx,
            delete_tx: Some(mgr_delete_tx),
            default_status: "Open".into(),
            default_tag: "Identified Threat".into(),
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
            _ = cloned.start(event_rx, Some(evt_cloned), resptime_tx, 1).await;
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

        let s = arc_backlog.to_alarm_json().unwrap();

        info!("alarm json:\n{}", s);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_all_rules_always_active_n_stickydiff() {
        let directives =
            directive::load_directives(true, Some(vec!["directives".to_string(), "directive6".to_string()])).unwrap();
        let d = directives[0].clone();
        let asset = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());

        let mut intel_plugin = crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap();
        intel_plugin.checkers = Arc::new(vec![]); // disable, we're not testing this
        let intels = Arc::new(intel_plugin);

        let mut vuln_plugin = crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap();
        vuln_plugin.checkers = Arc::new(vec![]); // disable, we're not testing this
        let vulns = Arc::new(vuln_plugin);

        let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
        let (event_tx, event_rx) = broadcast::channel(10);
        let (bp_tx, _) = mpsc::channel::<()>(1);
        let (resptime_tx, _resptime_rx) = mpsc::channel::<f64>(128);

        let (mut log_writer, log_tx) = LogWriter::new(true).unwrap();
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
            directive: d.clone(),
            asset,
            intels,
            vulns,
            event: Some(Arc::new(evt_cloned.clone())),
            bp_tx,
            delete_tx: Some(mgr_delete_tx),
            default_status: "Open".into(),
            default_tag: "Identified Threat".into(),
            min_alarm_lifetime: 0,
            med_risk_min: 3,
            med_risk_max: 5,
            intel_private_ip: true,
            log_tx,
        };
        let backlog = Backlog::new(&opt).unwrap();
        let _detached = task::spawn(async move {
            _ = backlog.start(event_rx, Some(evt_cloned), resptime_tx, 1).await;
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
        // these matching event should be captured by first rule, but only when there's
        // uniq SRC_PORT (sticky_different)

        // this should increase risk to 1 (Low)
        evt.plugin_sid = 2;
        evt.src_port = 31337;
        evt.id = "6".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;

        evt.id = "7".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("backlog can't find new unique value in stickydiff field"));

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
        let directives =
            directive::load_directives(true, Some(vec!["directives".to_string(), "directive5".to_string()])).unwrap();
        let d = directives[0].clone();
        let asset = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let intels = Arc::new(crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap());
        let vulns = Arc::new(crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap());
        let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
        let (_, event_rx) = broadcast::channel(10);
        let (bp_tx, _bp_rx) = mpsc::channel::<()>(8);
        let (resptime_tx, _resptime_rx) = mpsc::channel::<f64>(128);

        info!("about to start blocking");
        let (mut log_writer, log_tx) = LogWriter::new(true).unwrap();
        let _ = thread::spawn(move || {
            log_writer.listener().unwrap();
        });

        info!("done spawn blocking");

        let evt = NormalizedEvent {
            plugin_id: 1337,
            plugin_sid: 1,
            custom_label1: "label".into(),
            custom_data1: "data".into(),
            ..Default::default()
        };

        let _detached = task::spawn(async move {
            let opt = BacklogOpt {
                directive: d,
                asset,
                intels,
                vulns,
                event: Some(Arc::new(evt.clone())),
                bp_tx,
                delete_tx: Some(mgr_delete_tx),
                default_status: "Open".into(),
                default_tag: "Identified Threat".into(),
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

#[tokio::test]
async fn test_intel_vuln_preservation() {
    use std::thread;

    use tokio::sync::mpsc;

    use crate::{directive, intel, log_writer::LogWriter, vuln};

    // Test that intels and vulns are preserved in BacklogOpt cloning
    let directives =
        directive::load_directives(true, Some(vec!["directives".to_string(), "directive5".to_string()])).unwrap();
    let d = directives[0].clone();
    let asset = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
    let intels = Arc::new(intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap());
    let vulns = Arc::new(vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap());
    let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
    let (bp_tx, _) = mpsc::channel::<()>(1);
    let (mut log_writer, log_tx) = LogWriter::new(true).unwrap();
    let _ = thread::spawn(move || {
        log_writer.listener().unwrap();
    });

    let opt = BacklogOpt {
        directive: d.clone(),
        asset: asset.clone(),
        intels: intels.clone(),
        vulns: vulns.clone(),
        event: None,
        delete_tx: Some(mgr_delete_tx),
        default_status: "Open".into(),
        default_tag: "Identified Threat".into(),
        min_alarm_lifetime: 0,
        med_risk_min: 3,
        med_risk_max: 6,
        intel_private_ip: true,
        log_tx,
        bp_tx,
    };

    // Test cloning preserves intels and vulns
    let cloned_opt = opt.clone();
    assert!(Arc::ptr_eq(&cloned_opt.intels, &opt.intels));
    assert!(Arc::ptr_eq(&cloned_opt.vulns, &opt.vulns));

    // Test BacklogOpt spread syntax preserves intels and vulns (like in
    // get_backlog_opt)
    let spread_opt = BacklogOpt { event: None, delete_tx: opt.delete_tx.clone(), ..opt.clone() };
    assert!(Arc::ptr_eq(&spread_opt.intels, &opt.intels));
    assert!(Arc::ptr_eq(&spread_opt.vulns, &opt.vulns));

    // Test backlog creation preserves intels and vulns
    let backlog = Backlog::new(&opt).unwrap();
    assert!(backlog.intels.is_some());
    assert!(backlog.vulns.is_some());
    if let Some(ref backlog_intels) = backlog.intels {
        assert!(Arc::ptr_eq(backlog_intels, &opt.intels));
    }
    if let Some(ref backlog_vulns) = backlog.vulns {
        assert!(Arc::ptr_eq(backlog_vulns, &opt.vulns));
    }
}
