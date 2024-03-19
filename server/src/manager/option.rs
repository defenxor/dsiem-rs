use mini_moka::sync::Cache;
use tokio::sync::{broadcast, mpsc, Notify};

use crate::{
    allocator::ThreadAllocation, asset::NetworkAssets, directive::Directive, intel::IntelPlugin,
    vuln::VulnPlugin,
};
use std::{sync::Arc, time::Duration};

use super::ManagerReport;

#[derive(Clone)]
pub struct LazyLoaderConfig {
    dirs_idle_timeout_sec: u64,
    dirs_idle_timeout_checker_interval_sec: u64,
    pub cache: Cache<u64, ()>,
}

impl LazyLoaderConfig {
    pub fn new(ttl_directives: usize, dirs_idle_timeout_sec: u64) -> Self {
        Self {
            dirs_idle_timeout_sec,
            dirs_idle_timeout_checker_interval_sec: 60, // default to 1 minute
            cache: Cache::builder()
                .max_capacity(ttl_directives as u64)
                .time_to_idle(Duration::from_secs(dirs_idle_timeout_sec))
                .build(),
        }
    }
    pub fn with_dirs_idle_timeout_checker_interval_sec(mut self, seconds: u64) -> Self {
        self.dirs_idle_timeout_checker_interval_sec = seconds;
        self
    }
    pub fn get_idle_timeout(&self) -> u64 {
        self.dirs_idle_timeout_sec
    }
    pub fn get_idle_timeout_checker_interval(&self) -> u64 {
        self.dirs_idle_timeout_checker_interval_sec
    }
}

#[derive(Clone)]
pub struct ManagerOpt {
    pub test_env: bool,
    pub reload_backlogs: bool,
    pub lazy_loader: Option<LazyLoaderConfig>,
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
    pub default_status: String,
    pub default_tag: String,
    pub med_risk_min: u8,
    pub med_risk_max: u8,
    pub report_tx: mpsc::Sender<ManagerReport>,
    pub max_eps: u32,
    pub max_queue: usize,
    pub thread_allocation: ThreadAllocation,
    pub tokio_handle: tokio::runtime::Handle,
    pub notifier: Arc<Notify>,
}
