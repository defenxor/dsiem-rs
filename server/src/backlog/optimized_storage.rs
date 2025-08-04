use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc,
    },
};

use arcstr::ArcStr;
use parking_lot::RwLock;

use crate::{backlog::CustomData, intel::IntelResult, vuln::VulnResult};

/// Optimized storage structure that reduces lock contention
/// by separating frequently accessed data from rarely changed data
#[derive(Debug)]
pub struct OptimizedBacklogStorage {
    // Hot data - frequently accessed/modified
    pub hot_data: Arc<RwLock<BacklogHotData>>,

    // Cold data - rarely modified after creation
    pub cold_data: BacklogColdData,

    // Atomic counters to avoid locks for simple operations
    pub current_stage: AtomicU8,
    pub risk: AtomicU8,
    pub created_time: AtomicU64,
    pub update_time: AtomicU64,
}

#[derive(Debug, Default)]
pub struct BacklogHotData {
    pub src_ips: HashSet<IpAddr>,
    pub dst_ips: HashSet<IpAddr>,
    pub src_socketaddr: HashSet<SocketAddr>,
    pub dst_socketaddr: HashSet<SocketAddr>,
    pub networks: HashSet<ArcStr>,
    pub intel_hits: HashSet<IntelResult>,
    pub vulnerabilities: HashSet<VulnResult>,
    pub custom_data: HashSet<CustomData>,
    pub risk_class: ArcStr,
}

#[derive(Debug)]
pub struct BacklogColdData {
    pub id: String,
    pub title: ArcStr,
    pub status: ArcStr,
    pub tag: ArcStr,
    pub kingdom: ArcStr,
    pub category: ArcStr,
    pub priority: u8,
    pub highest_stage: u8,
    pub min_alarm_lifetime: i64,
    pub med_risk_min: u8,
    pub med_risk_max: u8,
    pub intel_private_ip: bool,
    pub directive_id: u64,
    pub all_rules_always_active: bool,
}

#[allow(clippy::too_many_arguments)]
impl OptimizedBacklogStorage {
    pub fn new(
        id: String,
        title: ArcStr,
        status: ArcStr,
        tag: ArcStr,
        kingdom: ArcStr,
        category: ArcStr,
        priority: u8,
        directive_id: u64,
        all_rules_always_active: bool,
    ) -> Self {
        Self {
            hot_data: Arc::new(RwLock::new(BacklogHotData::default())),
            cold_data: BacklogColdData {
                id,
                title,
                status,
                tag,
                kingdom,
                category,
                priority,
                highest_stage: 1,
                min_alarm_lifetime: 0,
                med_risk_min: 3,
                med_risk_max: 6,
                intel_private_ip: false,
                directive_id,
                all_rules_always_active,
            },
            current_stage: AtomicU8::new(1),
            risk: AtomicU8::new(0),
            created_time: AtomicU64::new(0),
            update_time: AtomicU64::new(0),
        }
    }

    /// Batch update multiple fields to reduce lock acquisition
    pub fn batch_update_ips_and_ports(&self, src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16) {
        let mut hot = self.hot_data.write();
        hot.src_ips.insert(src_ip);
        hot.dst_ips.insert(dst_ip);
        hot.src_socketaddr.insert(SocketAddr::new(src_ip, src_port));
        hot.dst_socketaddr.insert(SocketAddr::new(dst_ip, dst_port));

        // Clean up default IPs if we have multiple entries
        if hot.src_ips.len() > 1 {
            hot.src_ips.remove(&IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
        }
        if hot.dst_ips.len() > 1 {
            hot.dst_ips.remove(&IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
        }
    }

    /// Get read-only snapshot of hot data
    pub fn get_hot_data_snapshot(&self) -> BacklogHotData {
        self.hot_data.read().clone()
    }

    /// Compare and swap risk value atomically
    pub fn compare_and_swap_risk(&self, expected: u8, new: u8) -> bool {
        self.risk.compare_exchange(expected, new, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Batch update intel and vulnerability results to reduce lock contention
    pub fn batch_update_intel_vuln(&self, intel_hits: HashSet<IntelResult>, vulnerabilities: HashSet<VulnResult>) {
        let mut hot_data = self.hot_data.write();
        hot_data.intel_hits.extend(intel_hits);
        hot_data.vulnerabilities.extend(vulnerabilities);
    }

    /// Update networks efficiently
    pub fn update_networks(&self, networks: Vec<ArcStr>) {
        let mut hot_data = self.hot_data.write();
        for network in networks {
            hot_data.networks.insert(network);
        }
    }

    /// Get atomic values without locking
    pub fn get_atomic_values(&self) -> (u8, u8, u64, u64) {
        (
            self.current_stage.load(Ordering::Acquire),
            self.risk.load(Ordering::Acquire),
            self.created_time.load(Ordering::Acquire),
            self.update_time.load(Ordering::Acquire),
        )
    }

    /// Batch update atomic values to reduce memory barriers
    pub fn batch_update_atomics(&self, stage: Option<u8>, risk: Option<u8>, update_time: Option<u64>) {
        if let Some(s) = stage {
            self.current_stage.store(s, Ordering::Release);
        }
        if let Some(r) = risk {
            self.risk.store(r, Ordering::Release);
        }
        if let Some(t) = update_time {
            self.update_time.store(t, Ordering::Release);
        }
    }
}

#[derive(Debug, Clone)]
pub struct BacklogHotDataClone {
    pub src_ips: HashSet<IpAddr>,
    pub dst_ips: HashSet<IpAddr>,
    pub networks: HashSet<ArcStr>,
    pub intel_hits: HashSet<IntelResult>,
    pub vulnerabilities: HashSet<VulnResult>,
    pub custom_data: HashSet<CustomData>,
    pub risk_class: ArcStr,
}

impl Clone for BacklogHotData {
    fn clone(&self) -> Self {
        Self {
            src_ips: self.src_ips.clone(),
            dst_ips: self.dst_ips.clone(),
            src_socketaddr: self.src_socketaddr.clone(),
            dst_socketaddr: self.dst_socketaddr.clone(),
            networks: self.networks.clone(),
            intel_hits: self.intel_hits.clone(),
            vulnerabilities: self.vulnerabilities.clone(),
            custom_data: self.custom_data.clone(),
            risk_class: self.risk_class.clone(),
        }
    }
}
