use tokio::sync::{broadcast, mpsc, Notify};

use crate::{
    allocator::ThreadAllocation, asset::NetworkAssets, backlog::spawner::LazyLoaderConfig,
    directive::Directive, intel::IntelPlugin, vuln::VulnPlugin,
};
use std::sync::Arc;

use super::ManagerReport;

#[derive(Clone)]
pub struct FilterOpt {
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
