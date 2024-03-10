use std::{
    thread::{self, sleep},
    time::Duration,
};

use axum::{extract::State, routing::post, Json, Router};
use dsiem::{
    directive::load_directives,
    manager::FilterTarget,
    rule::{SIDPair, TaxoPair},
};
use dsiem::{event::NormalizedEvent, rule};
use rayon::prelude::*;
use tokio::sync::{
    broadcast::{channel, Sender},
    mpsc,
};
use tower_http::timeout::TimeoutLayer;
use tracing::{debug, info, warn};

const BIND_ADDR: &str = "127.0.0.1:6667";
const CHANNEL_CAPACITY: usize = 10000;
const DIRECTIVES_PER_THREAD: usize = 5000;
const RAYON_THREAD_POOL_SIZE: usize = 4;

fn main() {
    tracing_subscriber::fmt::init();
    let (event_tx, _) = channel(CHANNEL_CAPACITY);
    let logger_tx = event_tx.clone();
    let processor_tx = event_tx.clone();

    let mut handlers = vec![];

    let targets = get_targets();

    let use_rayon = std::env::var("USE_RAYON")
        .unwrap_or(false.to_string())
        .parse::<bool>()
        .unwrap();

    let h = if use_rayon {
        thread::spawn(move || {
            processor_rayon(processor_tx, targets);
        })
    } else {
        thread::spawn(move || {
            processor(processor_tx, targets);
        })
    };
    handlers.push(h);

    sleep(Duration::from_secs(1));
    let h = thread::spawn(move || {
        server(event_tx);
    });
    handlers.push(h);

    let h = thread::spawn(move || loop {
        sleep(Duration::from_secs(5));
        info!("queue length: {}", logger_tx.len());
    });
    handlers.push(h);

    for h in handlers {
        if h.join().is_err() {
            break;
        }
    }
}

fn get_targets() -> Vec<FilterTarget> {
    let directives = load_directives(false, None).unwrap();
    let mut targets = vec![];

    for d in directives {
        let (sid_pairs, taxo_pairs) = rule::get_quick_check_pairs(&d.rules);
        let contains_pluginrule = !sid_pairs.is_empty();
        let contains_taxorule = !taxo_pairs.is_empty();
        let (tx, _) = mpsc::channel::<NormalizedEvent>(1);
        let t = FilterTarget {
            id: d.id,
            tx,
            sid_pairs,
            taxo_pairs,
            contains_pluginrule,
            contains_taxorule,
        };
        targets.push(t);
    }
    targets
}

pub fn quick_check_taxo_rule(pairs: &[TaxoPair], e: &NormalizedEvent) -> bool {
    pairs
        .par_iter()
        .filter(|v| v.product.clone().into_iter().any(|x| *x == e.product))
        .any(|v| v.category == e.category)
}

pub fn quick_check_plugin_rule(pairs: &[SIDPair], e: &NormalizedEvent) -> bool {
    pairs
        .par_iter()
        .filter(|v| v.plugin_id == e.plugin_id)
        .any(|v| v.plugin_sid.clone().into_iter().any(|x| x == e.plugin_sid))
}

fn quick_discard_rayon(p: &FilterTarget, event: &NormalizedEvent) -> bool {
    (p.contains_pluginrule && !quick_check_plugin_rule(&p.sid_pairs, event))
        || (p.contains_taxorule && !quick_check_taxo_rule(&p.taxo_pairs, event))
}

fn quick_discard(p: &FilterTarget, event: &NormalizedEvent) -> bool {
    (p.contains_pluginrule && !rule::quick_check_plugin_rule(&p.sid_pairs, event))
        || (p.contains_taxorule && !rule::quick_check_taxo_rule(&p.taxo_pairs, event))
}

fn processor_rayon(event_tx: Sender<NormalizedEvent>, targets: Vec<FilterTarget>) {

    let pool_size = std::env::var("RAYON_THREAD_POOL_SIZE")
        .unwrap_or(RAYON_THREAD_POOL_SIZE.to_string())
        .parse::<usize>()
        .unwrap();

    rayon::ThreadPoolBuilder::new()
        .num_threads(pool_size)
        .build_global()
        .unwrap();

    info!(
        "processing {} total directives with {} rayon threadpool",
        targets.len(),
        pool_size
    );

    let handle = thread::spawn(move || {
        let mut rx = event_tx.subscribe();
        loop {
            let event = match rx.blocking_recv() {
                Ok(event) => event,
                Err(e) => {
                    warn!("failed to receive event: {}", e);
                    continue;
                }
            };
            debug!("processing event: {:?}", event);
            let matched_dirs: Vec<&FilterTarget> = targets
                .par_iter()
                .filter(|p| !quick_discard_rayon(p, &event))
                .collect();
            debug!(
                event.id,
                "event matched rules in {} directive(s)",
                matched_dirs.len()
            );
        }
    });

    _ = handle.join();
}

fn processor(event_tx: Sender<NormalizedEvent>, targets: Vec<FilterTarget>) {

    let chunk_size = std::env::var("DIRECTIVES_PER_THREAD")
        .unwrap_or(DIRECTIVES_PER_THREAD.to_string())
        .parse::<usize>()
        .unwrap();

    let r = targets.chunks(chunk_size).collect::<Vec<_>>();
    let mut chunks = vec![];
    for c in r {
        chunks.push(c.to_owned());
    }
    info!(
        "processing {} total directives with {} threads (max {} directives per thread)",
        targets.len(),
        chunks.len(),
        chunk_size
    );
    let mut handles = vec![];
    for (i, c) in chunks.into_iter().enumerate() {
        let mut rx = event_tx.subscribe();
        let h = thread::spawn(move || loop {
            let event = match rx.blocking_recv() {
                Ok(event) => event,
                Err(e) => {
                    warn!("failed to receive event: {}", e);
                    continue;
                }
            };
            debug!(thread.id = i, "processing event: {:?}", event);
            let matched_dirs: Vec<&FilterTarget> =
                c.iter().filter(|p| !quick_discard(p, &event)).collect();
            debug!(
                thread.id = i,
                event.id,
                "event matched rules in {} directive(s)",
                matched_dirs.len()
            );
        });
        handles.push(h);
    }

    for h in handles {
        _ = h.join();
    }
}

#[derive(Clone)]
struct AppState {
    event_tx: Sender<NormalizedEvent>,
}

#[tokio::main(flavor = "current_thread")]
async fn server(event_tx: Sender<NormalizedEvent>) {
    let state = AppState { event_tx };
    let router = Router::new()
        .route("/events", post(handler))
        .route("/events/", post(handler))
        .with_state(state)
        .layer(TimeoutLayer::new(Duration::from_secs(3)));
    let listener = tokio::net::TcpListener::bind(BIND_ADDR).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}

async fn handler(State(state): State<AppState>, Json(event): Json<NormalizedEvent>) {
    if let Err(e) = state.event_tx.send(event) {
        warn!("failed to send event: {}", e);
    }
}
