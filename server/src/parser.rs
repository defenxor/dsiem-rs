use std::sync::Arc;

use arcstr::ArcStr;
use tokio::sync::{broadcast, mpsc, Mutex};

use crate::{
    asset::NetworkAssets,
    backlog::{
        manager::{
            spawner::{LazyLoaderConfig, Spawner, SpawnerOnDemandOption},
            ManagerOpt, ManagerReport, OpLoadParameter,
        },
        BacklogOpt,
    },
    directive::Directive,
    event::NormalizedEvent,
    filter::{FilterTarget, OnDemandIDMessage},
    intel::IntelPlugin,
    log_writer::LogWriterMessage,
    vuln::VulnPlugin,
};

const DIRECTIVE_ID_CHAN_QUEUE_SIZE: usize = 64;

pub struct ParserOpt {
    pub assets: Arc<NetworkAssets>,
    pub intels: Arc<IntelPlugin>,
    pub vulns: Arc<VulnPlugin>,
    pub intel_private_ip: bool,
    pub default_status: ArcStr,
    pub default_tag: ArcStr,
    pub min_alarm_lifetime: i64,
    pub med_risk_min: u8,
    pub med_risk_max: u8,
    pub backpressure_tx: mpsc::Sender<()>,
    pub reload_backlogs: bool,
    pub test_env: bool,
    pub max_delay: i64,
    pub cancel_tx: broadcast::Sender<()>,
    pub resptime_tx: mpsc::Sender<f64>,
    pub report_tx: mpsc::Sender<ManagerReport>,
    pub lazy_loader: Option<LazyLoaderConfig>,
    pub log_tx: crossbeam_channel::Sender<LogWriterMessage>,
    pub load_param: OpLoadParameter,
}

pub fn targets_and_spawner_from_directives(
    directives: &[Directive],
    preload_directives: bool,
    opt: &ParserOpt,
) -> (Vec<FilterTarget>, Spawner, Option<mpsc::Sender<OnDemandIDMessage>>) {
    let mut targets = vec![];
    let mut id_tx = None;
    let mut b_managers = if preload_directives {
        Spawner::All(vec![])
    } else {
        let (tx, rx) = mpsc::channel::<OnDemandIDMessage>(DIRECTIVE_ID_CHAN_QUEUE_SIZE);
        id_tx = Some(tx);
        let ondemand_opt = SpawnerOnDemandOption { directives: directives.to_vec(), id_rx: rx, manager_option: None };
        Spawner::OnDemand(vec![], ondemand_opt)
    };

    for directive in directives.iter() {
        // this is a one-to-one channel between manager filter thread and backlog
        // managers
        let (event_tx, event_rx) = mpsc::channel::<NormalizedEvent>(opt.load_param.limit_cap);

        let rx = Arc::new(Mutex::new(event_rx));

        let backlog_option = BacklogOpt {
            directive: directive.clone(),
            asset: opt.assets.clone(),
            intels: opt.intels.clone(),
            vulns: opt.vulns.clone(),
            intel_private_ip: opt.intel_private_ip,
            default_status: opt.default_status.clone(),
            default_tag: opt.default_tag.clone(),
            min_alarm_lifetime: opt.min_alarm_lifetime,
            med_risk_min: opt.med_risk_min,
            med_risk_max: opt.med_risk_max,
            bp_tx: opt.backpressure_tx.clone(),
            log_tx: opt.log_tx.clone(),
            event: None,
            delete_tx: None,
        };

        let manager_opt = ManagerOpt {
            backlog_option,
            test_env: opt.test_env,
            reload_backlogs: opt.reload_backlogs,
            max_delay: opt.max_delay,
            cancel_tx: opt.cancel_tx.clone(),
            resptime_tx: opt.resptime_tx.clone(),
            report_tx: opt.report_tx.clone(),
            lazy_loader: opt.lazy_loader.clone(),
            load_param: opt.load_param.clone(),
        };

        b_managers.insert(directive.id, manager_opt, rx);

        FilterTarget::insert(directive.id, &directive.rules, event_tx.clone(), &mut targets);
    }
    (targets, b_managers, id_tx)
}
