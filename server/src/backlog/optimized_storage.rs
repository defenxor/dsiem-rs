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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use arcstr::ArcStr;

    use super::{BacklogHotData, OptimizedBacklogStorage};
    use crate::{backlog::CustomData, intel::IntelResult, vuln::VulnResult};

    fn create_test_storage() -> OptimizedBacklogStorage {
        OptimizedBacklogStorage::new(
            "test-id".to_string(),
            "test-title".into(),
            "test-status".into(),
            "test-tag".into(),
            "test-kingdom".into(),
            "test-category".into(),
            1,
            100,
            false,
        )
    }

    #[test]
    fn test_new_storage() {
        let storage = create_test_storage();

        // Check cold data
        assert_eq!(storage.cold_data.id, "test-id");
        assert_eq!(storage.cold_data.title, ArcStr::from("test-title"));
        assert_eq!(storage.cold_data.status, ArcStr::from("test-status"));
        assert_eq!(storage.cold_data.tag, ArcStr::from("test-tag"));
        assert_eq!(storage.cold_data.kingdom, ArcStr::from("test-kingdom"));
        assert_eq!(storage.cold_data.category, ArcStr::from("test-category"));
        assert_eq!(storage.cold_data.priority, 1);
        assert_eq!(storage.cold_data.directive_id, 100);
        assert!(!storage.cold_data.all_rules_always_active);

        // Check atomic values
        assert_eq!(storage.current_stage.load(std::sync::atomic::Ordering::Acquire), 1);
        assert_eq!(storage.risk.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(storage.created_time.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(storage.update_time.load(std::sync::atomic::Ordering::Acquire), 0);

        // Check hot data is initialized
        let hot_data = storage.hot_data.read();
        assert!(hot_data.src_ips.is_empty());
        assert!(hot_data.dst_ips.is_empty());
        assert!(hot_data.src_socketaddr.is_empty());
        assert!(hot_data.dst_socketaddr.is_empty());
        assert!(hot_data.networks.is_empty());
        assert!(hot_data.intel_hits.is_empty());
        assert!(hot_data.vulnerabilities.is_empty());
        assert!(hot_data.custom_data.is_empty());
    }

    #[test]
    fn test_batch_update_ips_and_ports() {
        let storage = create_test_storage();
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let src_port = 8080;
        let dst_port = 80;

        storage.batch_update_ips_and_ports(src_ip, dst_ip, src_port, dst_port);

        let hot_data = storage.hot_data.read();
        assert!(hot_data.src_ips.contains(&src_ip));
        assert!(hot_data.dst_ips.contains(&dst_ip));
        assert!(hot_data.src_socketaddr.contains(&SocketAddr::new(src_ip, src_port)));
        assert!(hot_data.dst_socketaddr.contains(&SocketAddr::new(dst_ip, dst_port)));
    }

    #[test]
    fn test_batch_update_ips_and_ports_cleanup_default() {
        let storage = create_test_storage();
        let default_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let real_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Add default IP first
        storage.batch_update_ips_and_ports(default_ip, default_ip, 0, 0);

        // Add real IP
        storage.batch_update_ips_and_ports(real_ip, real_ip, 8080, 80);

        let hot_data = storage.hot_data.read();
        // Default IPs should be removed when we have real IPs
        assert!(!hot_data.src_ips.contains(&default_ip));
        assert!(!hot_data.dst_ips.contains(&default_ip));
        assert!(hot_data.src_ips.contains(&real_ip));
        assert!(hot_data.dst_ips.contains(&real_ip));
    }

    #[test]
    fn test_get_hot_data_snapshot() {
        let storage = create_test_storage();
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        storage.batch_update_ips_and_ports(src_ip, dst_ip, 8080, 80);

        let snapshot = storage.get_hot_data_snapshot();
        assert!(snapshot.src_ips.contains(&src_ip));
        assert!(snapshot.dst_ips.contains(&dst_ip));
    }

    #[test]
    fn test_compare_and_swap_risk() {
        let storage = create_test_storage();

        // Initial risk is 0
        assert_eq!(storage.risk.load(std::sync::atomic::Ordering::Acquire), 0);

        // Try to swap from 0 to 5 - should succeed
        assert!(storage.compare_and_swap_risk(0, 5));
        assert_eq!(storage.risk.load(std::sync::atomic::Ordering::Acquire), 5);

        // Try to swap from 0 to 10 - should fail (current value is 5)
        assert!(!storage.compare_and_swap_risk(0, 10));
        assert_eq!(storage.risk.load(std::sync::atomic::Ordering::Acquire), 5);

        // Try to swap from 5 to 10 - should succeed
        assert!(storage.compare_and_swap_risk(5, 10));
        assert_eq!(storage.risk.load(std::sync::atomic::Ordering::Acquire), 10);
    }

    #[test]
    fn test_batch_update_intel_vuln() {
        let storage = create_test_storage();

        let mut intel_hits = HashSet::new();
        let intel_result = IntelResult {
            provider: "test-provider".to_string(),
            term: "192.168.1.1".to_string(),
            result: "test-result".to_string(),
        };
        intel_hits.insert(intel_result.clone());

        let mut vulnerabilities = HashSet::new();
        let vuln_result = VulnResult {
            provider: "test-vuln-provider".to_string(),
            term: "192.168.1.1:80".to_string(),
            result: "test-vuln-result".to_string(),
        };
        vulnerabilities.insert(vuln_result.clone());

        storage.batch_update_intel_vuln(intel_hits, vulnerabilities);

        let hot_data = storage.hot_data.read();
        assert!(hot_data.intel_hits.contains(&intel_result));
        assert!(hot_data.vulnerabilities.contains(&vuln_result));
    }

    #[test]
    fn test_update_networks() {
        let storage = create_test_storage();

        let networks = vec!["network1".into(), "network2".into(), "network3".into()];

        storage.update_networks(networks);

        let hot_data = storage.hot_data.read();
        assert!(hot_data.networks.contains(&ArcStr::from("network1")));
        assert!(hot_data.networks.contains(&ArcStr::from("network2")));
        assert!(hot_data.networks.contains(&ArcStr::from("network3")));
    }

    #[test]
    fn test_get_atomic_values() {
        let storage = create_test_storage();

        // Set some values
        storage.current_stage.store(3, std::sync::atomic::Ordering::Release);
        storage.risk.store(7, std::sync::atomic::Ordering::Release);
        storage.created_time.store(1000, std::sync::atomic::Ordering::Release);
        storage.update_time.store(2000, std::sync::atomic::Ordering::Release);

        let (stage, risk, created, updated) = storage.get_atomic_values();
        assert_eq!(stage, 3);
        assert_eq!(risk, 7);
        assert_eq!(created, 1000);
        assert_eq!(updated, 2000);
    }

    #[test]
    fn test_batch_update_atomics() {
        let storage = create_test_storage();

        // Update only stage and risk
        storage.batch_update_atomics(Some(5), Some(8), None);

        assert_eq!(storage.current_stage.load(std::sync::atomic::Ordering::Acquire), 5);
        assert_eq!(storage.risk.load(std::sync::atomic::Ordering::Acquire), 8);
        assert_eq!(storage.update_time.load(std::sync::atomic::Ordering::Acquire), 0); // Should be unchanged

        // Update only update_time
        storage.batch_update_atomics(None, None, Some(3000));

        assert_eq!(storage.current_stage.load(std::sync::atomic::Ordering::Acquire), 5); // Should be unchanged
        assert_eq!(storage.risk.load(std::sync::atomic::Ordering::Acquire), 8); // Should be unchanged
        assert_eq!(storage.update_time.load(std::sync::atomic::Ordering::Acquire), 3000);
    }

    #[test]
    fn test_hot_data_clone() {
        let mut hot_data = BacklogHotData::default();

        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        hot_data.src_ips.insert(src_ip);

        let network: ArcStr = "test-network".into();
        hot_data.networks.insert(network.clone());

        let intel_result = IntelResult {
            provider: "test-provider".to_string(),
            term: "192.168.1.1".to_string(),
            result: "test-result".to_string(),
        };
        hot_data.intel_hits.insert(intel_result.clone());

        let vuln_result = VulnResult {
            provider: "test-vuln-provider".to_string(),
            term: "192.168.1.1:80".to_string(),
            result: "test-vuln-result".to_string(),
        };
        hot_data.vulnerabilities.insert(vuln_result.clone());

        let custom_data = CustomData { label: "test-label".into(), content: "test-content".into() };
        hot_data.custom_data.insert(custom_data.clone());

        hot_data.risk_class = "high".into();

        let cloned = hot_data.clone();

        assert_eq!(cloned.src_ips, hot_data.src_ips);
        assert_eq!(cloned.networks, hot_data.networks);
        assert_eq!(cloned.intel_hits, hot_data.intel_hits);
        assert_eq!(cloned.vulnerabilities, hot_data.vulnerabilities);
        assert_eq!(cloned.custom_data, hot_data.custom_data);
        assert_eq!(cloned.risk_class, hot_data.risk_class);
    }
}
