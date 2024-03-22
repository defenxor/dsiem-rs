use tokio::sync::{broadcast, mpsc};

use crate::backlog::{spawner::LazyLoaderConfig, BacklogOpt};

use super::{ManagerReport, OpLoadParameter};

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
    pub report_interval: u64,
    pub load_param: OpLoadParameter,
}
