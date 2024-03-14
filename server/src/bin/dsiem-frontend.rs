use std::{
    net::{IpAddr, SocketAddr},
    process::ExitCode,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Error, Result};
use clap::{arg, command, Args, Parser, Subcommand};
use dsiem::{config, eps_limiter::EpsLimiter, server, tracer, worker};
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
    time::sleep,
};
use tracing::{debug, error, info};

#[derive(Parser)]
#[command(
    author("https://github.com/defenxor/dsiem-rs"),
    version,
    about = "Dsiem frontend server",
    long_about = "Dsiem frontend server\n\n\
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
        about = "Start Dsiem frontend server",
        long_about = "Start the Dsiem frontend server",
        name = "serve"
    )]
    ServeCommand(ServeArgs),
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// IP address for the HTTP server to listen on
    #[arg(
        short('a'),
        long = "ip-address",
        env = "DSIEM_ADDRESS",
        value_name = "ip",
        default_value = "0.0.0.0"
    )]
    address: String,

    /// TCP port for the HTTP server to listen on
    #[arg(
        short('p'),
        long = "tcp-port",
        env = "DSIEM_PORT",
        value_name = "tcp",
        default_value_t = 8080
    )]
    port: u16,

    /// Unique node name to use when deployed in cluster mode
    #[arg(short('n'), long = "node", env = "DSIEM_NODE", value_name = "string")]
    node: String,

    // Maximum expected rate of incoming events/second
    #[arg(
        short('e'),
        long = "max_eps",
        env = "DSIEM_MAXEPS",
        value_name = "number",
        default_value_t = 1000
    )]
    max_eps: u64,

    // Minimum expected rate of incoming events/second
    #[arg(
        short('i'),
        long = "min_eps",
        env = "DSIEM_MINEPS",
        value_name = "number",
        default_value_t = 100
    )]
    min_eps: u64,

    /// Nats address to use for frontend - backend communication
    #[arg(
        long = "msq",
        env = "DSIEM_MSQ",
        value_name = "string",
        default_value = "nats://dsiem-nats:4222"
    )]
    msq: String,
    /// Length of queue for unprocessed events, setting this to 0 will use 1,000,000 events to emulate unbounded queue
    #[arg(
        short('q'),
        long = "max_queue",
        env = "DSIEM_MAXQUEUE",
        value_name = "events",
        default_value_t = 25000
    )]
    max_queue: usize,
    /// Whether to allow configuration file update through HTTP
    #[arg(
        long = "writable-config",
        env = "DSIEM_WRITEABLECONFIG",
        value_name = "boolean",
        default_value = "false"
    )]
    writable_config: bool,
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
    /// Export traces data to opentelemetry collector
    #[arg(
        long = "otel-tracing-enabled",
        env = "DSIEM_OTEL_TRACING_ENABLED",
        value_name = "boolean",
        default_value_t = false
    )]
    enable_tracing: bool,
    /// Endpoint of the opentelemetry collector
    #[arg(
        long = "otel-endpoint",
        env = "DSIEM_OTEL_ENDPOINT",
        value_name = "string",
        default_value = "http://localhost:4317"
    )]
    otel_endpoint: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match serve(true, true, Cli::parse()).await.is_ok() {
        true => ExitCode::SUCCESS,
        false => ExitCode::FAILURE,
    }
}

fn log_startup_err(context: &str, err: Error) -> Error {
    error!("error {}: {}", context, err);
    err
}

async fn serve(listen: bool, require_logging: bool, args: Cli) -> Result<()> {
    let test_env = args.test_env;
    let verbosity = if args.debug {
        1
    } else if args.trace {
        2
    } else {
        args.verbosity
    };
    let SubCommands::ServeCommand(sargs) = args.subcommand;
    let log_format = if args.use_json {
        tracer::LogType::Json
    } else {
        tracer::LogType::Plain
    };
    let otel_config = tracer::OtelConfig {
        tracing_enabled: sargs.enable_tracing,
        otlp_endpoint: sargs.otel_endpoint,
        service_name: sargs.node.to_owned(),
        ..Default::default()
    };
    let subscriber = tracer::setup(verbosity, log_format, otel_config.clone())
        .map_err(|e| log_startup_err("setting up tracer", e))?;
    let setup_result = tracing::subscriber::set_global_default(subscriber);
    if require_logging {
        setup_result?;
    }
    let mut set = JoinSet::new();

    IpAddr::from_str(sargs.address.as_str())
        .map_err(|e| log_startup_err("parsing address parameter", e.into()))?;

    if sargs.port == 0 {
        return Err(log_startup_err(
            "parsing port parameter",
            anyhow!("port cannot be 0"),
        ));
    }

    let max_queue = if sargs.max_queue == 0 {
        1_000_000
    } else {
        sargs.max_queue
    };

    let (event_tx, event_rx) = broadcast::channel(max_queue);
    let (bp_tx, bp_rx) = mpsc::channel::<bool>(8);
    let (cancel_tx, cancel_rx) = broadcast::channel::<()>(1);

    let c = cancel_tx.clone();
    ctrlc::set_handler(move || {
        let _ = c.send(());
    })?;

    let eps_limiter = Arc::new(EpsLimiter::new(sargs.min_eps, sargs.max_eps)?);

    set.spawn({
        let lim = eps_limiter.clone();
        let tx = cancel_tx.clone();
        async move {
            lim.start(tx, bp_rx)
                .await
                .map_err(|e| log_startup_err("starting eps limiter thread", e))
        }
    });

    set.spawn({
        let nats_url = sargs.msq.clone();
        async move {
            let opt = worker::FrontendOpt {
                event_rx,
                bp_tx,
                cancel_rx,
                nats_url,
                nats_capacity: max_queue,
            };
            let w = worker::Worker {};
            w.frontend_start(opt)
                .await
                .map_err(|e| anyhow!("frontend worker error: {:?}", e))
        }
    });

    let addr = sargs.address + ":" + sargs.port.to_string().as_str();
    info!(
        "starting dsiem frontend server listening on {} using message queue at {}",
        addr, sargs.msq
    );

    debug!("saving status and tags to dsiem_config.json for UI to read");
    config::write_dsiem_config(test_env, sargs.status, sargs.tags)?;

    let c = cancel_tx.clone();
    set.spawn(async move {
        let app = server::app(test_env, sargs.writable_config, eps_limiter, event_tx)?;
        let listener = tokio::net::TcpListener::bind(addr.clone()).await?;
        let signal = async move {
            let mut rx = c.subscribe();
            let _ = rx.recv().await;
        };
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(signal)
        .await
        .map_err(|e| anyhow!("serve error: {:?}", e))
    });

    if listen {
        while let Some(Ok(res)) = set.join_next().await {
            if let Err(e) = res {
                error!("{:?}", e);
                _ = cancel_tx.send(());
                return Err(e);
            }
        }
    } else {
        sleep(Duration::from_secs(1)).await; // gives time for all spawns to await
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use tracing_test::traced_test;

    #[test]
    fn test_default_cli_param() {
        let args = Cli::parse_from([
            "dsiem-frontend",
            "--test-env",
            "serve",
            "-n",
            "dsiem-frontend-0",
        ]);
        assert!(args.test_env);
        assert!(!args.debug);
        assert!(!args.trace);
        assert!(!args.use_json);
        assert_eq!(args.verbosity, 0);
        let SubCommands::ServeCommand(sargs) = args.subcommand;

        assert_eq!(sargs.max_eps, 1000);
        assert_eq!(sargs.min_eps, 100);
        assert_eq!(sargs.msq, "nats://dsiem-nats:4222");
        assert_eq!(sargs.node, "dsiem-frontend-0");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    #[traced_test]
    async fn test_serve() {
        let cli = Cli::parse_from([
            "dsiem-frontend",
            "--test-env",
            "--json",
            "serve",
            "-n",
            "dsiem-frontend-0",
            "-p",
            "0",
        ]);
        let res = serve(false, false, cli).await;
        assert!(logs_contain("port cannot be 0"));
        assert!(res.is_err());

        let cli = Cli::parse_from([
            "dsiem-frontend",
            "--test-env",
            "--json",
            "serve",
            "-n",
            "dsiem-frontend-0",
        ]);
        let res = serve(false, false, cli).await;
        assert!(logs_contain("starting"));
        assert!(res.is_ok());

        let mut pty = rexpect::spawn(
            "docker run --name nats-main -p 42224:42224 --rm -it nats -p 42224",
            Some(5000),
        )
        .unwrap();
        pty.exp_string("Server is ready").unwrap();

        let cli = Cli::parse_from([
            "dsiem-frontend",
            "--test-env",
            "serve",
            "-n",
            "dsiem-frontend-0",
            "--msq",
            "nats://127.0.0.1:42224",
        ]);
        let res = serve(false, false, cli).await;
        if let Err(ref e) = res {
            let s = e.to_string();
            // ignore harmless Ctrl-C error
            if !s.contains("Ctrl-C") {
                assert!(res.is_ok())
            }
        }
    }
}
