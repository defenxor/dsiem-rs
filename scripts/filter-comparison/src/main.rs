/*!

This example provides a way to easily evaluate the performance difference between using rayon vs 
multiple dedicated threads to execute the hot-code path where events are checked against all directive rules.

At the time of writing, dedicated threads are more performant than rayon for dsiem specific use case, 
and so it is the one used in directive manager and rule.

Usage:

Activate rayon by setting the environment variable `USE_RAYON` to `true`, or set it
to `false` or unset to use dedicated threads.

Other environment variables that can be set are:
- `RAYON_THREAD_POOL_SIZE` to set the number of threads used by rayon
- `DIRECTIVES_PER_THREAD` to set the number of directives processed by each dedicated thread

After setting the environment variables:

- Put a directive.json file with at least a thousand entries in /configs directory, i.e.:
  
  mkdir -p ./target/debug/configs && ln -s path/to/directive.json ./target/debug/configs/directive.json

- Execute one of the following command to start the server (release version is more performant):

  cargo run -p filter-comparison
  cargo build --release -p filter-comparison && ./target/release/filter-comparison

- Send a POST request using dtester (https://github.com/defenxor/dsiem/tree/master/cmd/dtester):

  ./dtester dsiem -d 192.168.0.1 -f <path-to-directive.json-above> -p 6667 -r [eps]

- Try different values for `eps` and compare the performance between rayon and dedicated threads.

*/

use std::{
    thread::{self, sleep},
    time::Duration,
};

use axum::{extract::State, routing::post, Json, Router};
use dsiem::{
    directive::load_directives,
    manager::DirectiveParams,
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

    let use_rayon = std::env::var("USE_RAYON")
        .unwrap_or(false.to_string())
        .parse::<bool>()
        .unwrap();

    let h = if use_rayon {
        thread::spawn(move || {
            processor_rayon(processor_tx);
        })
    } else {
        thread::spawn(move || {
            processor(processor_tx);
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

fn get_params() -> Vec<DirectiveParams> {
    let directives = load_directives(false, None).unwrap();
    let mut params = vec![];

    for d in directives {
        let (sid_pairs, taxo_pairs) = rule::get_quick_check_pairs(&d.rules);
        let contains_pluginrule = !sid_pairs.is_empty();
        let contains_taxorule = !taxo_pairs.is_empty();
        let (tx, _) = mpsc::channel::<NormalizedEvent>(1);
        let p = DirectiveParams {
            id: d.id,
            tx,
            sid_pairs,
            taxo_pairs,
            contains_pluginrule,
            contains_taxorule,
        };
        params.push(p);
    }
    params
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

fn quick_discard_rayon(p: &DirectiveParams, event: &NormalizedEvent) -> bool {
    (p.contains_pluginrule && !quick_check_plugin_rule(&p.sid_pairs, event))
        || (p.contains_taxorule && !quick_check_taxo_rule(&p.taxo_pairs, event))
}

fn quick_discard(p: &DirectiveParams, event: &NormalizedEvent) -> bool {
    (p.contains_pluginrule && !rule::quick_check_plugin_rule(&p.sid_pairs, event))
        || (p.contains_taxorule && !rule::quick_check_taxo_rule(&p.taxo_pairs, event))
}

fn processor_rayon(event_tx: Sender<NormalizedEvent>) {
    let params = get_params();

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
        params.len(),
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
            let matched_dirs: Vec<&DirectiveParams> = params
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

fn processor(event_tx: Sender<NormalizedEvent>) {
    let params = get_params();

    let chunk_size = std::env::var("DIRECTIVES_PER_THREAD")
        .unwrap_or(DIRECTIVES_PER_THREAD.to_string())
        .parse::<usize>()
        .unwrap();

    let r = params.chunks(chunk_size).collect::<Vec<_>>();
    let mut chunks = vec![];
    for c in r {
        chunks.push(c.to_owned());
    }
    info!(
        "processing {} total directives with {} threads (max {} directives per thread)",
        params.len(),
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
            let matched_dirs: Vec<&DirectiveParams> =
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
