use std::{process::ExitCode, sync::Arc, thread};

use anyhow::{anyhow, Result};
use clap::{arg, command, Args, Parser, Subcommand};
use dsiem::{
    asset::NetworkAssets,
    backlog::loader::{self, LazyLoaderConfig},
    cmd_utils::{ctrlc_handler, log_startup_err, Validator as validator},
    config, directive,
    event::NormalizedEvent,
    filter::{self, Filter},
    intel,
    log_writer::LogWriter,
    messenger, parser, tracer, vuln, watchdog,
};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Notify};
use tracing::info;

#[derive(Parser)]
#[command(
    author("https://github.com/defenxor/dsiem-rs"),
    version,
    about = "Dsiem backend server",
    long_about = "Dsiem backend server\n\n\
    Dsiem is an event correlation engine for ELK stack.\n\
    Dsiem provides OSSIM-style correlation for normalized logs/events, and relies on\n\
    Filebeat, Logstash, and Elasticsearch to do the rest."
)]
struct Cli {
    #[command(subcommand)]
    subcommand: SubCommands,
    /// Increase logging verbosity
    #[arg(short('v'), long, action = clap::ArgAction::Count)]
    verbosity: u8,
    /// Enable debug output, for compatibility purpose
    #[arg(
        long = "debug",
        env = "DSIEM_DEBUG",
        value_name = "boolean",
        default_value_t = false
    )]
    debug: bool,
    /// Enable trace output, for compatibility purpose
    #[arg(
        long = "trace",
        env = "DSIEM_TRACE",
        value_name = "boolean",
        default_value_t = false
    )]
    trace: bool,
    /// Enable json-lines log output
    #[arg(
        short('j'),
        long = "json",
        env = "DSIEM_JSON",
        value_name = "boolean",
        default_value_t = false
    )]
    use_json: bool,
    /// Testing environment flag
    #[arg(long = "test-env", value_name = "boolean", default_value_t = false)]
    test_env: bool,
}

#[derive(Subcommand)]
enum SubCommands {
    #[command(
        about = "Start Dsiem backend server",
        long_about = "Start the Dsiem backend server",
        name = "serve"
    )]
    ServeCommand(ServeArgs),
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// Frontend URL to pull configuration from
    #[arg(
        short('f'),
        long = "frontend",
        env = "DSIEM_FRONTEND",
        value_name = "url",
        default_value = "http://frontend:8080"
    )]
    frontend: String,
    /// Unique node name to use when deployed in cluster mode
    #[arg(short('n'), long = "node", env = "DSIEM_NODE", value_name = "string")]
    node: String,
    /// Min. alarm lifetime in minutes. Backlog won't expire sooner than this regardless rule timeouts. This is to support processing of delayed events
    #[arg(
        short('l'),
        long,
        env = "DSIEM_MINALARMLIFETIME",
        value_name = "minutes",
        default_value_t = 0
    )]
    min_alarm_lifetime: u16,
    /// Alarm status to use, the first one will be assigned to new alarms
    #[arg(
        short('s'),
        long,
        env = "DSIEM_STATUS",
        value_name = "comma separated strings",
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "Open,In-Progress,Closed"
    )]
    status: Vec<String>,
    /// Alarm tags to use, the first one will be assigned to new alarms
    #[arg(
        short('t'),
        long,
        env = "DSIEM_TAGS",
        value_name = "comma separated strings",
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "Identified Threat,False Positive,Valid Threat,Security Incident"
    )]
    tags: Vec<String>,
    /// Minimum alarm risk value to be classified as Medium risk. Lower value than this will be classified as Low risk
    #[arg(
        long = "med_risk_min",
        value_name = "2 to 8",
        env = "DSIEM_MEDRISKMIN",
        default_value_t = 3
    )]
    med_risk_min: u8,
    /// Maximum alarm risk value to be classified as Medium risk. Higher value than this will be classified as High risk
    #[arg(
        long = "med_risk_max",
        value_name = "2 to 9",
        env = "DSIEM_MEDRISKMAX",
        default_value_t = 6
    )]
    med_risk_max: u8,
    // Maximum expected rate of events/second
    #[arg(
        short('e'),
        long = "max_eps",
        value_name = "number",
        env = "DSIEM_MAXEPS",
        default_value_t = 1000
    )]
    max_eps: u32,
    /// Nats address to use for frontend - backend communication
    #[arg(
        long = "msq",
        env = "DSIEM_MSQ",
        value_name = "string",
        default_value = "nats://dsiem-nats:4222"
    )]
    msq: String,
    /// Cache expiration time in minutes for intel and vuln query results
    #[arg(
        short('c'),
        long = "cache",
        env = "DSIEM_CACHEDURATION",
        value_name = "minutes",
        default_value_t = 10
    )]
    cache_duration: u8,
    /// Length of queue for unprocessed events, rounded to the next power of 2.
    ///
    /// For example, setting this to 1000 will mean 1024 events queue length,
    /// 12000 will mean 16384 events queue length, and so on.
    ///
    /// Setting this to 0 will use 524,288 events to emulate unbounded queue for
    /// compatibility with dsiem-go behavior, which is no longer recommended.
    ///
    /// Instead, this should be set to a reasonable value to avoid unnecessary memory allocation.
    #[arg(
        short('q'),
        long = "max_queue",
        env = "DSIEM_MAXQUEUE",
        value_name = "events",
        default_value_t = 32768
    )]
    max_queue: usize,
    /// Duration in seconds before resetting overload condition state
    #[arg(
        long = "hold_duration",
        env = "DSIEM_HOLDDURATION",
        value_name = "seconds",
        default_value_t = 10
    )]
    hold_duration: u8,
    /// Max. processing delay before throttling incoming events (under-pressure condition), 0 means disabled"
    #[arg(
        short = 'd',
        long = "max_delay",
        env = "DSIEM_MAXDELAY",
        value_name = "seconds",
        default_value_t = 180
    )]
    max_delay: u16,
    /// Check private IP addresses against threat intel
    #[arg(
        long = "intel_private_ip",
        env = "DSIEM_INTELPRIVATEIP",
        default_value_t = false
    )]
    intel_private_ip: bool,
    /// Save and reload running backlogs on restart
    #[arg(
        long = "reload-backlogs",
        env = "DSIEM_RELOAD_BACKLOGS",
        value_name = "boolean",
        default_value_t = true
    )]
    reload_backlogs: bool,
    /// Export traces data to opentelemetry collector
    #[arg(
        long = "otel-tracing-enabled",
        env = "DSIEM_OTEL_TRACING_ENABLED",
        value_name = "boolean",
        default_value_t = false
    )]
    enable_tracing: bool,
    /// Export metrics data to an opentelemetry collector
    #[arg(
        long = "otel-metrics-enabled",
        env = "DSIEM_OTEL_METRICS_ENABLED",
        value_name = "boolean",
        default_value_t = false
    )]
    enable_metrics: bool,
    /// Endpoint of the opentelemetry collector
    #[arg(
        long = "otel-endpoint",
        env = "DSIEM_OTEL_ENDPOINT",
        value_name = "string",
        default_value = "http://localhost:4317"
    )]
    otel_endpoint: String,
    /// Number of threads to use for events filtering, 0 means auto
    #[arg(
        long = "filter-threads",
        env = "DSIEM_FILTER_THREADS",
        value_name = "number",
        default_value_t = 0
    )]
    filter_threads: usize,
    /// Preload all directives on startup to increase performance
    #[arg(
        long = "preload-all-directives",
        env = "DSIEM_PRELOAD_DIRECTIVES",
        value_name = "bool",
        default_value_t = false
    )]
    preload_directives: bool,
    /// Duration in minutes to wait for idle directives before unloading them.
    ///
    /// Idle directives are those that have 0 backlogs for the specified duration.
    ///
    /// This is only applicable when preload-all-directives is false
    #[arg(
        long = "idle-directives-timeout",
        env = "DSIEM_DIRECTIVES_IDLE_TIMEOUT_MINUTES",
        value_name = "minutes",
        default_value_t = 10
    )]
    dir_idle_timeout: u16,
}

fn main() -> ExitCode {
    match serve(true, true, Cli::parse()).is_ok() {
        true => ExitCode::SUCCESS,
        false => ExitCode::FAILURE,
    }
}

fn serve(listen: bool, require_logging: bool, args: Cli) -> Result<()> {
    let test_env = args.test_env;

    let SubCommands::ServeCommand(sargs) = args.subcommand;

    let max_delay = validator::max_delay(sargs.max_delay)
        .map_err(|e| log_startup_err("reading max_delay", e))?;

    validator::verify_risk_boundaries(sargs.med_risk_min, sargs.med_risk_max)
        .map_err(|e| log_startup_err("reading med_risk_min and med_risk_max", e))?;

    validator::verify_dirs_idle_timeout_minutes(sargs.dir_idle_timeout)
        .map_err(|e| log_startup_err("reading dir_idle_timeout", e))?;

    let min_alarm_lifetime = validator::min_alarm_lifetime(sargs.min_alarm_lifetime);
    let max_queue = validator::max_queue(sargs.max_queue);
    let log_verbosity = validator::log_verbosity(args.trace, args.debug, args.verbosity);
    let log_format = validator::log_format(args.use_json);

    let otel_config = tracer::OtelConfig {
        tracing_enabled: sargs.enable_tracing,
        metrics_enabled: sargs.enable_metrics,
        otlp_endpoint: sargs.otel_endpoint,
        service_name: sargs.node.to_owned(),
    };

    let (event_tx, _) = broadcast::channel::<NormalizedEvent>(max_queue);
    let (bp_tx, bp_rx) = mpsc::channel::<()>(8);
    let (cancel_tx, cancel_rx) = broadcast::channel::<()>(1);

    ctrlc_handler(cancel_tx.clone(), !test_env)
        .map_err(|e| log_startup_err("setting up ctrl-c handler", e))?;

    config::download_files(
        test_env,
        Some(vec!["dl_config".to_string()]),
        sargs.frontend.clone(),
        sargs.node,
    )
    .map_err(|e| log_startup_err("downloading config", e))?;

    let directives = directive
    // todo: maybe replace this kludgy way of loading test directive5
    ::load_directives(
        test_env,
        Some(vec!["directives".to_string(), "directive5".to_string()]),
    )
    .map_err(|e| log_startup_err("loading directives", e))?;

    let eps = Arc::new(watchdog::eps::Eps::default());
    let n = directives.len();

    let thread_allocation = validator::thread_allocation(n, sargs.max_eps, sargs.filter_threads)
        .map_err(|e| log_startup_err("allocating threads", e))?;

    let (report_tx, report_rx) = mpsc::channel::<filter::ManagerReport>(n);
    let (resptime_tx, resptime_rx) = mpsc::channel::<f64>(n);

    let max_eps = sargs.max_eps;
    let event_tx_clone = event_tx.clone();
    let cancel_tx_clone = cancel_tx.clone();
    let eps_clone = eps.clone();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(thread_allocation.tokio_threads)
        .enable_all()
        .build()
        .map_err(|e| log_startup_err("building tokio runtime", e.into()))?;

    let _handle_watchdog = rt.spawn(async move {
        let opt = watchdog::WatchdogOpt {
            event_tx: event_tx_clone,
            resptime_rx,
            report_rx,
            ttl_directives: n,
            cancel_tx: cancel_tx_clone,
            report_interval: watchdog::REPORT_INTERVAL_IN_SECONDS,
            max_eps,
            otel_config,
            eps: eps_clone,
            log_verbosity,
            log_format,
            require_logging,
        };
        let mut w = watchdog::Watchdog::default();
        w.start(opt)
            .await
            .map_err(|e| anyhow!("watchdog error: {:?}", e))
    });

    let assets = Arc::new(
        NetworkAssets::new(test_env, Some(vec!["assets".to_string()]))
            .map_err(|e| log_startup_err("loading assets", e))?,
    );

    info!(
        "starting dsiem backend server with frontend {} and message queue {}",
        sargs.frontend, sargs.msq
    );

    let notifier = Arc::new(Notify::new());
    let waiter = notifier.clone();

    let backend_asset = assets.clone();
    let backend_tx = event_tx.clone();

    let _handle_worker = rt.spawn(async move {
        let opt = messenger::BackendOpt {
            event_tx: backend_tx,
            bp_rx,
            cancel_rx,
            assets: backend_asset,
            nats_url: sargs.msq,
            hold_duration: sargs.hold_duration,
            nats_capacity: max_queue,
            eps,
            waiter,
        };
        let w = messenger::Worker {};
        w.backend_start(opt)
            .await
            .map_err(|e| anyhow!("worker error: {:?}", e))
    });

    let intels = Arc::new(
        intel::load_intel(test_env, Some(vec!["intel_vuln".to_string()]))
            .map_err(|e| log_startup_err("loading intels", e))?,
    );

    let vulns = Arc::new(
        vuln::load_vuln(test_env, Some(vec!["intel_vuln".to_string()]))
            .map_err(|e| log_startup_err("loading vulns", e))?,
    );

    let lazy_loader = match sargs.preload_directives {
        true => None,
        false => Some(LazyLoaderConfig::new(
            n,
            (sargs.dir_idle_timeout * 60) as u64,
        )),
    };

    let mut log_writer = LogWriter::new(test_env)?;
    let log_tx = log_writer.sender.clone();
    let _ = thread::spawn(move || log_writer.listener());

    let load_param = validator::load_param(sargs.max_queue, sargs.max_eps);

    info!("backend started with max single event processing time: {} ms, queue limit: {} events, quick check threads: {}, backlog threads: {}, ttl directives: {}",
        load_param.max_wait.as_millis(),
        load_param.limit_cap,
        thread_allocation.filter_threads,
        thread_allocation.tokio_threads,
        n
    );

    let opt = parser::ParserOpt {
        test_env,
        reload_backlogs: sargs.reload_backlogs,
        lazy_loader: lazy_loader.clone(),
        assets,
        intels,
        vulns,
        max_delay,
        min_alarm_lifetime,
        backpressure_tx: bp_tx,
        resptime_tx,
        cancel_tx: cancel_tx.clone(),
        med_risk_max: sargs.med_risk_max,
        med_risk_min: sargs.med_risk_min,
        default_status: sargs.status[0].clone(),
        default_tag: sargs.tags[0].clone(),
        intel_private_ip: sargs.intel_private_ip,
        report_tx,
        load_param: load_param.clone(),
        log_tx,
    };

    let (filter_targets, manager_loader, id_tx) =
        parser::targets_and_loader_from_directives(&directives, sargs.preload_directives, &opt);

    // start manager loader first before filter

    let handle_manager = manager_loader.run(rt.handle().clone())?;

    // if preload_directives is false and reload_backlogs is true, we should instruct the loader to spawn those backlog managers that have
    // backlogs saved on disk

    if !sargs.preload_directives && sargs.reload_backlogs {
        if let Some(id_tx) = &id_tx {
            loader::load_with_spawner(test_env, id_tx.clone());
        }
    }

    let filter = Filter::new(filter::FilterOpt {
        lazy_loader,
        thread_allocation,
        cancel_tx,
        notifier,
    });

    let id_tx_clone = id_tx.clone();
    let handle_filter = thread::spawn(move || {
        filter
            .start(event_tx, filter_targets, id_tx_clone)
            .map_err(|e| anyhow!("filter error: {:?}", e))
    });

    if listen {
        _ = handle_manager.join();
        if let Ok(Err(e)) = handle_filter.join() {
            return Err(e);
        }
    } else {
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;
    use tracing::debug;
    use tracing_test::traced_test;

    #[test]
    fn test_default_cli_param_and_parser() {
        let args = Cli::parse_from([
            "dsiem-backend",
            "--test-env",
            "serve",
            "-n",
            "dsiem-backend-0",
        ]);

        assert!(args.test_env);
        assert!(!args.debug);
        assert!(!args.trace);
        assert!(!args.use_json);
        assert_eq!(args.verbosity, 0);
        let SubCommands::ServeCommand(sargs) = args.subcommand;
        assert_eq!(sargs.frontend, "http://frontend:8080");
        assert_eq!(sargs.hold_duration, 10);
        assert_eq!(sargs.cache_duration, 10);
        assert_eq!(sargs.max_delay, 180);
        assert_eq!(sargs.max_queue, 32768);
        assert_eq!(sargs.max_eps, 1000);
        assert_eq!(sargs.med_risk_max, 6);
        assert_eq!(sargs.med_risk_min, 3);
        assert_eq!(sargs.min_alarm_lifetime, 0);
        assert_eq!(sargs.msq, "nats://dsiem-nats:4222");
        assert_eq!(sargs.node, "dsiem-backend-0");
        assert!(!sargs.intel_private_ip);
        assert!(sargs.tags.iter().any(|x| x == "Valid Threat"));
        assert!(sargs.status.iter().any(|x| x == "Open"));
        assert!(sargs.reload_backlogs);
    }

    #[test]
    #[traced_test]
    fn test_serve_failure() {
        let cli = Cli::parse_from([
            "dsiem-backend",
            "--test-env",
            "--json",
            "serve",
            "-n",
            "dsiem-backend-0",
            "--med_risk_max",
            "11",
        ]);
        let res = serve(false, false, cli);
        // wrong med_risk_max
        // assert!(logs_contain("med_risk_max"));
        assert!(res.is_err());

        let cli = Cli::parse_from([
            "dsiem-backend",
            "--test-env",
            "--json",
            "serve",
            "-n",
            "dsiem-backend-0",
            "-f",
            "http://localhost:6666",
            "--max_queue",
            "0",
        ]);
        let res = serve(false, false, cli);
        // wrong frontend url
        // assert!(logs_contain("error downloading config"));
        assert!(res.is_err());
    }

    #[test]
    fn test_serve_success() {
        let file_list = r#"{ 
            "files" : [] 
        }"#;

        let mut server = mockito::Server::new_with_opts(mockito::ServerOpts {
            port: 19005,
            ..Default::default()
        });
        let url = server.url();
        debug!("using url: {}", url.clone());
        server
            .mock("GET", "/config/")
            .with_status(200)
            .with_body(file_list)
            .create();

        let mut pty = rexpect::spawn(
            "docker run --name nats-main-be -p 42225:42225 --rm -it nats -p 42225",
            Some(5000),
        )
        .unwrap();
        pty.exp_string("Server is ready").unwrap();

        let cli = Cli::parse_from([
            "dsiem-backend",
            "--test-env",
            "serve",
            "-n",
            "dsiem-backend-0",
            "-f",
            "http://127.0.0.1:19005",
            "--msq",
            "nats://127.0.0.1:42225",
        ]);
        let res = serve(false, false, cli);

        assert!(res.is_ok());
    }
}
