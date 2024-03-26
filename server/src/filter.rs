use std::{sync::Arc, thread, vec};

use anyhow::Result;
use mini_moka::sync::Cache;
use tokio::sync::{
    broadcast::{self, error::RecvError},
    mpsc, oneshot, Notify,
};
use tracing::{debug, error, info, info_span, trace, warn, Span};

use crate::{
    allocator::ThreadAllocation,
    backlog::manager::spawner::LazyLoaderConfig,
    event::NormalizedEvent,
    rule::{self, DirectiveRule},
    tracer,
};

pub struct FilterOpt {
    pub lazy_loader: Option<LazyLoaderConfig>,
    pub thread_allocation: ThreadAllocation,
    pub notifier: Arc<Notify>,
    pub cancel_tx: broadcast::Sender<()>,
}

// re-export
pub use crate::backlog::manager::ManagerReport;

mod cache;

#[derive(Clone)]
pub struct FilterTarget {
    pub id: u64,
    pub tx: mpsc::Sender<NormalizedEvent>,
    pub sid_pairs: Vec<rule::SIDPair>,
    pub taxo_pairs: Vec<rule::TaxoPair>,
    pub contains_pluginrule: bool,
    pub contains_taxorule: bool,
}

impl FilterTarget {
    pub fn insert(
        id: u64,
        rules: &[DirectiveRule],
        event_tx: mpsc::Sender<NormalizedEvent>,
        targets: &mut Vec<FilterTarget>,
    ) {
        let (mut sid_pairs, mut taxo_pairs) = rule::get_quick_check_pairs(rules);
        let contains_pluginrule = !sid_pairs.is_empty();
        let contains_taxorule = !taxo_pairs.is_empty();
        sid_pairs.shrink_to_fit();
        taxo_pairs.shrink_to_fit();
        targets.push(FilterTarget { id, tx: event_tx, sid_pairs, taxo_pairs, contains_pluginrule, contains_taxorule });
    }
}

pub type OnDemandIDMessage = (u64, oneshot::Sender<()>);

pub struct Filter {
    option: FilterOpt,
}

impl Filter {
    pub fn new(option: FilterOpt) -> Self {
        Self { option }
    }

    pub fn start(
        &self,
        publisher: broadcast::Sender<NormalizedEvent>,
        targets: Vec<FilterTarget>,
        id_tx: Option<mpsc::Sender<OnDemandIDMessage>>,
    ) -> Result<()> {
        let active_ids = match &self.option.lazy_loader {
            Some(l) => l.cache.clone(),
            None => Cache::builder().max_capacity(0).build(), // fix this
        };

        let preload_directives = self.option.lazy_loader.is_none();

        let dir_len = targets.len();
        let chunk_size = dir_len / self.option.thread_allocation.filter_threads;

        let r = targets.chunks(chunk_size).collect::<Vec<_>>();
        let mut chunks = vec![];
        for c in r {
            chunks.push(c.to_owned());
        }

        let mut handles = vec![];

        for (idx, c) in chunks.into_iter().enumerate() {
            let rx = publisher.subscribe();
            let id_tx = id_tx.clone();
            let active_ids = active_ids.clone();
            let span = Span::current();

            let handle =
                thread::spawn(move || Filter::event_handler(idx, rx, id_tx, preload_directives, active_ids, c, span));
            handles.push(handle);
        }

        self.option.notifier.notify_one();

        // drop publisher to signal all filter threads to exit
        drop(publisher);
        for h in handles {
            _ = h.join();
        }

        // tell all others to exit if they havent
        _ = self.option.cancel_tx.send(());

        info!("exiting filter main thread");
        Ok(())
    }

    fn event_handler(
        id: usize,
        mut rx: broadcast::Receiver<NormalizedEvent>,
        id_tx: Option<mpsc::Sender<OnDemandIDMessage>>,
        preload_directives: bool,
        active_ids: Cache<u64, ()>,
        c: Vec<FilterTarget>,
        span: Span,
    ) {
        let matched_with_event = |p: &FilterTarget, event: &NormalizedEvent| -> bool {
            (p.contains_pluginrule && rule::quick_check_plugin_rule(&p.sid_pairs, event))
                || (p.contains_taxorule && rule::quick_check_taxo_rule(&p.taxo_pairs, event))
        };

        let _h = span.entered();
        let filter_span = info_span!("filter thread", thread.id = id);
        let _h = filter_span.enter();

        // thread local cache for this specific chunk of directives
        let sid_cache = cache::create_sid_cache(&c);
        let sid_cache_enabled = !sid_cache.is_empty();
        let taxo_cache = cache::create_taxo_cache(&c);
        let taxo_cache_enabled = !taxo_cache.is_empty();

        loop {
            let mut event = match rx.blocking_recv() {
                Ok(event) => event,
                Err(RecvError::Lagged(n)) => {
                    warn!("filtering lagged and skipped {} events", n);
                    continue;
                }
                Err(RecvError::Closed) => {
                    info!("filtering event receiver closed");
                    break;
                }
            };

            // heuristic to filter out events that are not worth processing
            let found = (event.plugin_id != 0
                && event.plugin_sid != 0
                && sid_cache_enabled
                && sid_cache.get(&(event.plugin_id, event.plugin_sid)).is_some())
                || (
                    // check this only when there's no plugin rule match
                    !event.product.is_empty()
                        && !event.category.is_empty()
                        && taxo_cache_enabled
                        && taxo_cache.get(&(event.product.clone(), event.category.clone())).is_some()
                );

            if !found {
                // log level should match with its pair in messenger
                trace!(event.id, "event doesn't match any rule, skipping");
                continue;
            }

            // here we just need to find the directive(s) that match the event
            let matched_dirs: Vec<&FilterTarget> = c.iter().filter(|p| matched_with_event(p, &event)).collect();
            debug!(event.id, "event matched rules in {} directive(s)", matched_dirs.len());

            let distrib_span = info_span!("event distribution", event.id);
            tracer::set_parent_from_event(&distrib_span, &event);
            let _ = distrib_span.enter();
            tracer::store_parent_into_event(&distrib_span, &mut event);

            matched_dirs.iter().for_each(|d| {
                // if preload directive is false, send the directive id to the spawner
                // do this only when the directive isn't already in the active_ids
                if !preload_directives && !active_ids.contains_key(&d.id) {
                    if let Some(id_tx) = &id_tx {
                        let id_tx = id_tx.clone();
                        debug!(directive.id = d.id, "sending directive ID to spawner");
                        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

                        if let Err(e) = id_tx.blocking_send((d.id, tx)) {
                            error!(directive.id = d.id, event.id, "skipping, filter can't send id to spawner: {}", e);
                            return;
                        }
                        // waiting for the spawner to acknowledge backlog manager creation
                        debug!(directive.id = d.id, "waiting confirmation from spawner");
                        if let Err(e) = rx.blocking_recv() {
                            // failure could mean there's already an existing backlog manager for
                            // this directive so we should just try to
                            // send the event anyway
                            warn!(
                                directive.id = d.id,
                                event.id,
                                "spawner failed to confirm backlog manager creation: {}, will try to send the event \
                                 anyway",
                                e
                            );
                        }
                    }
                }

                debug!(directive.id = d.id, event.id, "sending event to backlog manager");
                if d.tx.try_send(event.clone()).is_err() {
                    warn!(directive.id = d.id, event.id, "backlog manager lagged or no longer active, dropping event");
                }
            });
        }
    }
}
