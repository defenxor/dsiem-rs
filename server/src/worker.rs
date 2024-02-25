// ch chan<- event.NormalizedEvent, msq string, msqPrefix string, nodeName string, confDir string, frontend string

use futures_lite::StreamExt;
use std::str;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{
        broadcast::{self, Sender},
        mpsc,
    },
    time::interval,
};

use crate::manager::UNBOUNDED_QUEUE_SIZE;
use crate::{
    asset::NetworkAssets,
    event::{self, NormalizedEvent},
    tracer,
};
use anyhow::{anyhow, Context, Result};
use tracing::{debug, error, info, info_span, trace};

const EVENT_SUBJECT: &str = "dsiem_events";
const BP_SUBJECT: &str = "dsiem_overload_signals";
const MIN_NATS_CAPACITY: usize = 1024;
const MAX_NATS_CAPACITY: usize = 10000;

async fn nats_client(nats_url: &str, capacity: &usize) -> Result<async_nats::Client> {
    // set sane boundaries for capacity
    let cap = match *capacity {
        UNBOUNDED_QUEUE_SIZE => MAX_NATS_CAPACITY,
        _ if *capacity < MIN_NATS_CAPACITY => MIN_NATS_CAPACITY,
        _ => *capacity,
    };
    let client = async_nats::ConnectOptions::new()
        .subscription_capacity(cap)
        .request_timeout(Some(std::time::Duration::from_secs(
            NATS_CONNECT_MAX_SECONDS,
        )))
        .event_callback(|event| async move {
            match event {
                async_nats::Event::Disconnected => debug!("nats disconnected"),
                async_nats::Event::Connected => debug!("nats reconnected"),
                async_nats::Event::ClientError(err) => {
                    debug!("nats client error occurred: {}", err)
                }
                other => debug!("nats event happened: {}", other),
            }
        })
        .connect(nats_url)
        .await?;
    Ok(client)
}

pub struct BackendOpt {
    pub nats_url: String,
    pub event_tx: broadcast::Sender<NormalizedEvent>,
    pub bp_rx: mpsc::Receiver<()>,
    pub cancel_rx: broadcast::Receiver<()>,
    pub hold_duration: u8,
    pub assets: Arc<NetworkAssets>,
    pub nats_capacity: usize,
}

pub struct FrontendOpt {
    pub nats_url: String,
    pub event_rx: broadcast::Receiver<NormalizedEvent>,
    pub bp_tx: mpsc::Sender<bool>,
    pub cancel_rx: broadcast::Receiver<()>,
    pub nats_capacity: usize,
}

const NATS_CONNECT_MAX_SECONDS: u64 = 5;
pub struct Worker {}

impl Worker {
    pub async fn frontend_start(&self, mut opt: FrontendOpt) -> Result<()> {
        let client = nats_client(&opt.nats_url, &opt.nats_capacity)
            .await
            .context(format!("cannot connect to {}", opt.nats_url))?;

        let mut subscription: async_nats::Subscriber = client
            .subscribe(BP_SUBJECT.into())
            .await
            .map_err(|e| anyhow!("{}", e))
            .context(format!(
                "cannot subscribe to {} from {}",
                BP_SUBJECT, opt.nats_url
            ))?;

        info!("listening for new back pressure signal");
        loop {
            tokio::select! {
                Some(message) = subscription.next() => {
                    if let Ok(v) = str::from_utf8(&message.payload) {
                        if v == "true" || v == "false" {
                            debug!("overload = {} signal received from backend", v);
                            opt.bp_tx.send(v == "true").await?;
                        } else {
                            error!("back pressure message contain bytes that cant be parsed, skipping it");
                        }
                    } else {
                        error!("back pressure message contain bytes that cant be parsed, skipping it");
                    }
                },
                Ok(event) = opt.event_rx.recv() => {
                    debug!("received new event from handler: {}", event.id);
                    let s = serde_json::to_string(&event)?;
                    if let Err(err) = client.publish(EVENT_SUBJECT.into(), s.into()).await {
                        error!("error sending event to nats: {}", err);
                    } else {
                        debug!("event {} sent to nats", event.id);
                    }
                },
                _ = opt.cancel_rx.recv() => {
                    info!("cancel signal received, exiting frontend-worker thread");
                    break;
                },
            }
        }
        Ok(())
    }

    pub async fn backend_start(&self, mut opt: BackendOpt) -> Result<()> {
        let client = nats_client(&opt.nats_url, &opt.nats_capacity)
            .await
            .context(format!("cannot connect to {}", opt.nats_url))?;

        let mut subscription = client
            .subscribe(EVENT_SUBJECT.into())
            .await
            .map_err(|e| anyhow!("{}", e))
            .context(format!(
                "cannot subscribe to dsiem_events from {}",
                opt.nats_url
            ))?;

        let mut reset_bp = interval(Duration::from_secs(opt.hold_duration.into()));
        let mut bp_state = false;

        info!("listening for new events");
        loop {
            tokio::select! {
                Some(message) = subscription.next() => {
                    if let Ok(v) = str::from_utf8(&message.payload) {

                        trace!("received new event from nats: {}", v);

                        if let Err(e) = self.handle_event_message(&opt.assets, &opt.event_tx, v) {
                            error!("{}", e);
                        }
                    } else {
                        error!("an event contain bytes that cant be parsed, skipping it");
                    }
                },
                _ = reset_bp.tick() => {
                    if bp_state {
                        if let Err(err) = client.publish(BP_SUBJECT.into(), "false".into()).await {
                            error!("error sending overload = false signal to frontend: {}", err);
                        } else {
                            info!("overload = false signal sent to frontend");
                            bp_state = false;
                        }
                    }
                },
                Some(_) = opt.bp_rx.recv() => {
                    debug!("received under pressure signal from backlogs");
                    reset_bp.reset();
                    if bp_state {
                        debug!("last under pressure signal is still active");
                        continue;
                    }
                    bp_state = true;
                    if let Err(err) = client.publish(BP_SUBJECT.into(), "true".into()).await {
                        error!("error sending overload = true signal to frontend: {}", err);
                    } else {
                        info!("overload = true signal sent to frontend");
                    }
                },
                _ = opt.cancel_rx.recv() => {
                    info!("cancel signal received, exiting worker thread");
                    break;
                },
            }
        }
        Ok(())
    }

    fn handle_event_message(
        &self,
        assets: &Arc<NetworkAssets>,
        event_tx: &Sender<event::NormalizedEvent>,
        payload_str: &str,
    ) -> Result<()> {
        let span = info_span!("backend handler", event = payload_str);
        _ = span.enter();

        let mut e = serde_json::from_str::<NormalizedEvent>(payload_str)
            .map_err(|e| anyhow!("cannot parse event from message queue: {}, skipping it", e))?;
        if !e.valid() {
            let err_text = format!("event {} is not valid, skipping it", e.id);
            return Err(anyhow!(err_text));
        }
        if assets.is_whitelisted(&e.src_ip) {
            debug!(e.id, "src_ip {} is whitelisted, skipping event", e.src_ip);
            return Ok(());
        }

        if !e.carrier.is_empty() {
            // use remote as current span's parent
            tracer::set_parent_from_event(&span, &e);
        }

        // set carrier's content to current span
        tracer::store_parent_into_event(&span, &mut e);

        let id = e.id.to_owned();
        if let Err(err) = event_tx.send(e) {
            let err_text = format!("cannot send event {}: {}, skipping it", id, err);
            return Err(anyhow!(err_text));
        }
        debug!("event {} broadcasted", id);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::{task, time::sleep};
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_backend_start() {
        let mut pty =
            rexpect::spawn("docker run -p 42222:42222 --rm -it nats -p 42222", None).unwrap();
        pty.exp_string("Server is ready").unwrap();

        let nats_url = "nats://127.0.0.1:42222";

        let assets = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let (event_tx, _) = broadcast::channel::<NormalizedEvent>(5);
        let (cancel_tx, cancel_rx) = broadcast::channel::<()>(5);
        let (bp_tx, bp_rx) = mpsc::channel::<()>(5);

        let opt = BackendOpt {
            nats_url: nats_url.to_string(),
            assets,
            event_tx,
            cancel_rx,
            bp_rx,
            hold_duration: 1,
            nats_capacity: 5,
        };

        let _detached = task::spawn(async {
            let w = Worker {};
            _ = w.backend_start(opt).await;
        });

        sleep(Duration::from_millis(3000)).await;
        assert!(logs_contain("listening for new events"));

        _ = bp_tx.send(()).await;
        _ = bp_tx.send(()).await;
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("received under pressure signal from backlogs"));
        assert!(logs_contain("overload = true signal sent to frontend"));
        assert!(logs_contain("last under pressure signal is still active"));

        let client = nats_client(nats_url, &5)
            .await
            .context(format!("cannot connect to {}", nats_url))
            .unwrap();

        let evt = NormalizedEvent {
            id: "1".to_string(),
            ..Default::default()
        };
        let payload_str = serde_json::to_string(&evt).unwrap();
        client
            .publish(EVENT_SUBJECT.into(), payload_str.into())
            .await
            .unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("received new event from nats"));
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("event 1 is not valid"));

        _ = cancel_tx.send(());
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("cancel signal received"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_frontend_start() {
        let mut pty =
            rexpect::spawn("docker run -p 42223:42223 --rm -it nats -p 42223", None).unwrap();
        pty.exp_string("Server is ready").unwrap();

        let nats_url = "nats://127.0.0.1:42223";

        let (event_tx, event_rx) = broadcast::channel::<NormalizedEvent>(5);
        let (cancel_tx, cancel_rx) = broadcast::channel::<()>(5);
        let (bp_tx, mut bp_rx) = mpsc::channel::<bool>(5);
        let opt = FrontendOpt {
            nats_url: nats_url.to_string(),
            event_rx,
            bp_tx,
            cancel_rx,
            nats_capacity: 5,
        };

        let _detached = task::spawn(async {
            let w = Worker {};
            _ = w.frontend_start(opt).await;
        });

        sleep(Duration::from_millis(3000)).await;
        assert!(logs_contain("listening for new back pressure signal"));

        let client = nats_client(nats_url, &5)
            .await
            .context(format!("cannot connect to {}", nats_url))
            .unwrap();

        let _detached = task::spawn(async move {
            bp_rx.recv().await;
        });

        client
            .publish(BP_SUBJECT.into(), "true".into())
            .await
            .unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("overload = true signal received from backend"));

        client
            .publish(BP_SUBJECT.into(), "foo".into())
            .await
            .unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain(
            "back pressure message contain bytes that cant be parsed"
        ));

        _ = event_tx.send(NormalizedEvent::default());
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("received new event from handler"));
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("sent to nats"));

        _ = cancel_tx.send(());
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("cancel signal received"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_handle_event_message() {
        let assets = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let (event_tx, mut event_rx) = broadcast::channel::<NormalizedEvent>(1);
        let w = Worker {};

        let res = w.handle_event_message(&assets, &event_tx, "foo");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("cannot parse event"));

        let mut event = NormalizedEvent::default();
        let payload_str = serde_json::to_string(&event).unwrap();

        let res = w.handle_event_message(&assets, &event_tx, &payload_str);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("is not valid"));

        event.plugin_id = 1001;
        event.plugin_sid = 50001;
        event.src_ip = "192.168.0.2".parse().unwrap();
        event.dst_ip = "0.0.0.0".parse().unwrap();
        event.sensor = "foo".to_owned();
        event.id = "foo".to_owned();
        event.title = "bar".to_owned();
        event.timestamp = chrono::Utc::now();

        let payload_str = serde_json::to_string(&event).unwrap();
        let res = w.handle_event_message(&assets, &event_tx, &payload_str);
        assert!(res.is_ok());
        assert!(logs_contain("whitelisted"));

        let h = task::spawn(async move { event_rx.recv().await });

        event.src_ip = "192.168.0.1".parse().unwrap();
        let payload_str = serde_json::to_string(&event).unwrap();
        let res = w.handle_event_message(&assets, &event_tx, &payload_str);
        assert!(res.is_ok());
        assert!(logs_contain("broadcasted"));

        h.abort();
        _ = h.await;

        let res = w.handle_event_message(&assets, &event_tx, &payload_str);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("cannot send event"));
    }
}
