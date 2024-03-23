use std::{sync::Arc, thread, time::Duration};

use backlog::manager;
use dsiem::{
    allocator::ThreadAllocation,
    asset::NetworkAssets,
    backlog::{
        self,
        manager::{spawner::LazyLoaderConfig, QueueMode},
    },
    directive::{self, Directive},
    event::NormalizedEvent,
    filter::{self, Filter, FilterOpt, ManagerReport},
    intel,
    log_writer::{LogWriter, LogWriterMessage},
    parser::{self, ParserOpt},
    vuln,
};
use tokio::{
    runtime::Handle,
    sync::{
        broadcast::{self, Sender},
        mpsc, Notify,
    },
    task,
    time::sleep,
};
use tracing::{debug, Instrument, Span};
use tracing_test::traced_test;

fn get_parser_opt(
    c: Sender<()>,
    r: mpsc::Sender<ManagerReport>,
    reload_backlogs: bool,
    lazy_loader: Option<LazyLoaderConfig>,
    log_tx: crossbeam_channel::Sender<LogWriterMessage>,
) -> ParserOpt {
    let (backpressure_tx, _) = mpsc::channel::<()>(8);
    let (resptime_tx, _) = mpsc::channel::<f64>(128);

    let assets = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
    let intels = Arc::new(intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap());
    let vulns = Arc::new(vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap());
    let load_param = backlog::manager::OpLoadParameter {
        max_wait: Duration::from_millis(100),
        limit_cap: 1000,
        queue_mode: QueueMode::Bounded,
    };
    ParserOpt {
        test_env: true,
        lazy_loader,
        reload_backlogs,
        assets,
        intels,
        vulns,
        intel_private_ip: false,
        max_delay: 0,
        min_alarm_lifetime: 0,
        backpressure_tx,
        cancel_tx: c,
        resptime_tx,
        default_status: "Open".to_string(),
        default_tag: "Identified Threat".to_string(),
        med_risk_min: 3,
        med_risk_max: 6,
        report_tx: r,
        load_param,
        log_tx,
    }
}

fn get_filter_opt(
    cancel_tx: broadcast::Sender<()>,
    lazy_loader: Option<LazyLoaderConfig>,
) -> FilterOpt {
    let notifier = Notify::new();
    FilterOpt {
        lazy_loader,
        thread_allocation: ThreadAllocation {
            filter_threads: 1,
            tokio_threads: 1,
        },
        notifier: Arc::new(notifier),
        cancel_tx,
    }
}
async fn run_manager(
    directives: Vec<Directive>,
    event_tx: broadcast::Sender<NormalizedEvent>,
    cancel_tx: broadcast::Sender<()>,
    report_tx: mpsc::Sender<ManagerReport>,
    reload_backlogs: bool,
    lazy_loader: Option<LazyLoaderConfig>,
) -> task::JoinHandle<()> {
    let opt = get_filter_opt(cancel_tx.clone(), lazy_loader.clone());
    let span = Span::current();
    let tx_clone = event_tx.clone();

    let mut log_writer = LogWriter::new(true).unwrap();
    let log_tx = log_writer.sender.clone();

    let preload_directives = lazy_loader.is_none();

    let (targets, loader, id_tx) = parser::targets_and_spawner_from_directives(
        &directives,
        preload_directives,
        &get_parser_opt(
            cancel_tx.clone(),
            report_tx.clone(),
            reload_backlogs,
            lazy_loader,
            log_tx,
        ),
    );
    task::spawn_blocking(move || {
        let _ = thread::spawn(move || log_writer.listener());
        let _h = span.entered();

        let _ = loader.run(Handle::current());

        if !preload_directives && reload_backlogs {
            if let Some(id_tx) = &id_tx {
                manager::spawner::load_with_spawner(true, id_tx.clone());
            }
        }

        let f = Filter::new(opt);
        _ = f.start(tx_clone, targets, id_tx);

        debug!("exiting filter and loader task");
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[traced_test]
async fn test_filter_and_loader_preload_dirs() {
    let directives = directive::load_directives(
        true,
        Some(vec!["directives".to_string(), "directive5".to_string()]),
    )
    .unwrap();
    let (cancel_tx, _) = broadcast::channel::<()>(1);
    let (report_tx, mut report_rx) = mpsc::channel::<filter::ManagerReport>(directives.len());

    let span = Span::current();
    let _report_receiver = task::spawn(
        async move {
            // test comparing report
            let rpt1 = ManagerReport {
                id: 1,
                active_backlogs: 1,
                timedout_backlogs: 0,
                matched_events: 0,
            };
            let mut rpt2 = ManagerReport {
                id: 1,
                active_backlogs: 1,
                timedout_backlogs: 0,
                matched_events: 0,
            };
            assert!(rpt1 == rpt2);
            rpt2.active_backlogs = 2;
            assert!(rpt1 != rpt2);
            while report_rx.recv().await.is_some() {
                debug!("report received");
            }
        }
        .instrument(span),
    );

    let (event_tx, _) = broadcast::channel(1024);

    let manager_handle = run_manager(
        directives.clone(),
        event_tx.clone(),
        cancel_tx.clone(),
        report_tx.clone(),
        false,
        None,
    )
    .await;

    let mut evt = NormalizedEvent {
        id: "0a".to_string(),
        plugin_id: 31337,
        plugin_sid: 2,
        custom_label1: "label".to_string(),
        custom_data1: "data".to_string(),
        ..Default::default()
    };

    sleep(Duration::from_millis(3000)).await;

    // assert that the backlog manager is listening for events
    assert!(logs_contain("listening for event directive.id=1"));

    // unmatched event
    event_tx.send(evt.clone()).unwrap();
    sleep(Duration::from_millis(2000)).await;

    assert!(logs_contain("event doesn't match any rule"));

    // matched event but not on the first rule
    evt.id = "0b".to_string();
    evt.plugin_id = 1337;
    event_tx.send(evt.clone()).unwrap();
    sleep(Duration::from_millis(2000)).await;
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
    sleep(Duration::from_millis(1000)).await;
    assert!(logs_contain("event sent downstream"));
    assert!(logs_contain(
        "found existing backlog that consumes the event"
    ));

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
    sleep(Duration::from_millis(2000)).await;
    assert!(logs_contain("report received"));

    // create another backlog
    evt.plugin_sid = 1;
    evt.id = "6".to_string();
    evt.timestamp = chrono::Utc::now();
    event_tx.send(evt.clone()).unwrap();
    sleep(Duration::from_millis(500)).await;
    assert!(logs_contain("creating new backlog"));

    _ = cancel_tx.send(());
    sleep(Duration::from_millis(4000)).await;
    drop(event_tx);
    sleep(Duration::from_millis(500)).await;
    assert!(logs_contain("manager exiting"));

    _ = manager_handle.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[traced_test]
async fn test_filter_and_loader_no_preload_dirs() {
    let directives = directive::load_directives(
        true,
        Some(vec!["directives".to_string(), "directive5".to_string()]),
    )
    .unwrap();
    let (cancel_tx, _) = broadcast::channel::<()>(1);
    let (report_tx, mut report_rx) = mpsc::channel::<filter::ManagerReport>(directives.len());

    let span = Span::current();
    let _report_receiver = task::spawn(
        async move {
            while report_rx.recv().await.is_some() {
                debug!("report received");
            }
        }
        .instrument(span),
    );

    let (event_tx, _) = broadcast::channel(1024);

    let l = LazyLoaderConfig::new(directives.len(), 100)
        .with_dirs_idle_timeout_checker_interval_sec(10);

    // this function should be the only location where reload_backlogs is true,
    // otherwise we risk having multiple tests trying to save/load/delete from disk

    let manager_handle = run_manager(
        directives.clone(),
        event_tx.clone(),
        cancel_tx.clone(),
        report_tx.clone(),
        true,
        Some(l.clone()),
    )
    .await;

    let mut evt = NormalizedEvent {
        id: "0a".to_string(),
        plugin_id: 31337,
        plugin_sid: 2,
        custom_label1: "label".to_string(),
        custom_data1: "data".to_string(),
        ..Default::default()
    };

    sleep(Duration::from_millis(1000)).await;

    // unmatched event
    event_tx.send(evt.clone()).unwrap();
    sleep(Duration::from_millis(2000)).await;

    assert!(logs_contain("event doesn't match any rule"));

    // matched event but not on the first rule
    evt.id = "0b".to_string();
    evt.plugin_id = 1337;
    event_tx.send(evt.clone()).unwrap();
    sleep(Duration::from_millis(2000)).await;
    assert!(logs_contain("event doesn't match first rule"));

    // matched event 1
    evt.plugin_sid = 1;
    evt.id = "1".to_string();
    event_tx.send(evt.clone()).unwrap();
    sleep(Duration::from_millis(1000)).await;

    // assert that the backlog manager is listening for events
    assert!(logs_contain("listening for event directive.id=1"));

    assert!(logs_contain("creating new backlog"));

    // matched event 2
    evt.id = "2".to_string();
    event_tx.send(evt.clone()).unwrap();
    sleep(Duration::from_millis(1000)).await;
    assert!(logs_contain("event sent downstream"));
    assert!(logs_contain(
        "found existing backlog that consumes the event"
    ));

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
    sleep(Duration::from_millis(2000)).await;
    assert!(logs_contain("report received"));

    // create another backlog
    evt.plugin_sid = 1;
    evt.id = "6".to_string();
    evt.timestamp = chrono::Utc::now();
    event_tx.send(evt.clone()).unwrap();
    sleep(Duration::from_millis(500)).await;
    assert!(logs_contain("creating new backlog"));

    // cancel signal, should also trigger saving to disk

    _ = cancel_tx.send(());
    sleep(Duration::from_millis(1000)).await;
    logs_contain("backlogs saved");

    drop(event_tx);
    sleep(Duration::from_millis(5000)).await;

    assert!(logs_contain("manager exiting"));

    _ = manager_handle.await;

    debug!("now will restart to simulate reloading saved backlogs");

    let (event_tx, _) = broadcast::channel::<NormalizedEvent>(1);
    let manager_handle = run_manager(
        directives.clone(),
        event_tx.clone(),
        cancel_tx.clone(),
        report_tx.clone(),
        true,
        Some(l),
    )
    .await;

    sleep(Duration::from_millis(2000)).await;

    assert!(logs_contain(
        "found 1 saved backlogs, instructing spawner to activate"
    ));
    sleep(Duration::from_millis(1000)).await;
    assert!(logs_contain(
        "spawner received directive ID from filter directive.id=1"
    ));

    _ = cancel_tx.send(());
    drop(event_tx);
    sleep(Duration::from_millis(3000)).await;
    _ = manager_handle.await;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[traced_test]
async fn test_filter_and_loader_directives_timeout() {
    let directives = directive::load_directives(
        true,
        Some(vec!["directives".to_string(), "directive5".to_string()]),
    )
    .unwrap();
    let (cancel_tx, _) = broadcast::channel::<()>(1);
    let (report_tx, mut report_rx) = mpsc::channel::<filter::ManagerReport>(directives.len());

    let span = Span::current();
    let _report_receiver = task::spawn(
        async move {
            while report_rx.recv().await.is_some() {
                debug!("report received");
            }
        }
        .instrument(span),
    );

    let (event_tx, _) = broadcast::channel(1024);

    let loader =
        LazyLoaderConfig::new(directives.len(), 3).with_dirs_idle_timeout_checker_interval_sec(1);

    let manager_handle = run_manager(
        directives.clone(),
        event_tx.clone(),
        cancel_tx.clone(),
        report_tx.clone(),
        false,
        Some(loader),
    )
    .await;

    let mut evt = NormalizedEvent {
        id: "0a".to_string(),
        plugin_id: 31337,
        plugin_sid: 2,
        custom_label1: "label".to_string(),
        custom_data1: "data".to_string(),
        ..Default::default()
    };

    sleep(Duration::from_millis(1000)).await;
    // matched event 1
    evt.plugin_sid = 1;
    evt.plugin_id = 1337;
    evt.id = "1".to_string();
    event_tx.send(evt.clone()).unwrap();
    sleep(Duration::from_millis(1000)).await;

    // assert that the backlog manager is listening for events
    assert!(logs_contain("listening for event directive.id=1"));

    assert!(logs_contain("creating new backlog"));

    // should be logged every second until backlog expires
    sleep(Duration::from_millis(500)).await;
    assert!(logs_contain("backlogs is not empty resetting idle timeout"));

    // backlog should've expired, also the idle timeout of 3 secs after that
    sleep(Duration::from_secs(15)).await;
    assert!(logs_contain(
        "idle timeout reached, exiting backlog manager"
    ));

    // sending another event should instantiate a new backlog manager
    evt.id = "10".to_string();
    event_tx.send(evt).unwrap();
    sleep(Duration::from_millis(5000)).await;

    assert!(logs_contain(
        "backlog::manager: received event directive.id=1 event.id=\"10\""
    ));

    // teardown
    _ = cancel_tx.send(());
    drop(event_tx);
    _ = manager_handle.await;
}
