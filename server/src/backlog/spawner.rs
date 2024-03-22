use std::{sync::Arc, thread};

use mini_moka::sync::Cache;
use tokio::{sync::{mpsc, oneshot, Mutex}, task};
use tracing::{debug, error, info, warn, Instrument, Span};

use crate::{directive::Directive, event::NormalizedEvent};

use super::manager::{BacklogManager, ManagerOpt};
use anyhow::{Result, anyhow};

#[derive(Clone)]
pub struct LazyLoaderConfig {
    dirs_idle_timeout_sec: u64,
    dirs_idle_timeout_checker_interval_sec: u64,
    pub cache: Cache<u64, ()>,
}

impl LazyLoaderConfig {
    pub fn new(ttl_directives: usize, dirs_idle_timeout_sec: u64) -> Self {
        Self {
            dirs_idle_timeout_sec,
            dirs_idle_timeout_checker_interval_sec: 60, // default to 1 minute
            cache: Cache::new(ttl_directives as u64),
        }
    }
    pub fn with_dirs_idle_timeout_checker_interval_sec(mut self, seconds: u64) -> Self {
        self.dirs_idle_timeout_checker_interval_sec = seconds;
        self
    }
    pub fn get_idle_timeout(&self) -> u64 {
        self.dirs_idle_timeout_sec
    }
    pub fn get_idle_timeout_checker_interval(&self) -> u64 {
        self.dirs_idle_timeout_checker_interval_sec
    }
}


pub struct BacklogManagerId {
    pub id: u64,
    pub upstream_rx: Arc<Mutex<mpsc::Receiver<NormalizedEvent>>>,
}

pub enum ManagerLoader {
    OnDemand(Vec<Arc<BacklogManagerId>>, SpawnerOnDemandOption),
    All(Vec<BacklogManager>),
}

impl ManagerLoader {
    pub fn insert(&mut self, id: u64, manager_opt: ManagerOpt, upstream_rx: Arc<Mutex<mpsc::Receiver<NormalizedEvent>>>) {
        match self {
            ManagerLoader::OnDemand(ref mut b, ondemand_opt) => {
                b.push(Arc::new(BacklogManagerId {
                    id,
                    upstream_rx,
                }));
                if ondemand_opt.manager_option.is_none() {
                    ondemand_opt.manager_option = Some(manager_opt);
                };
            }
            ManagerLoader::All(ref mut b) => {
                let m = BacklogManager::new(
                    manager_opt, upstream_rx
                );
                b.push(m);
            }
        }        
    }
    
    pub fn run(self, rt: tokio::runtime::Handle) -> Result<thread::JoinHandle<()>> {
        match self {
            ManagerLoader::OnDemand(b, ondemand_opt) => {
                spawner_ondemand(b, ondemand_opt, rt)
            }
            ManagerLoader::All(ref b) => {
                spawner(b.to_vec(), rt)
            }
        }
    }



}

fn spawner(dir_managers: Vec<BacklogManager>, rt: tokio::runtime::Handle) -> Result<thread::JoinHandle<()>> {
    let span = Span::current();
    let h = thread::spawn(move || {
        let _h = span.entered();
        let span = Span::current();
        rt.block_on(async move {
            let _h = span.entered();
            let mut set: task::JoinSet<_> = tokio::task::JoinSet::new();
            for dir_manager in dir_managers {
                let span = Span::current();
                let (ready_tx, ready_rx) = oneshot::channel::<()>();
                let id = dir_manager.id;
                set.spawn(async move {
                    let _ = dir_manager.start(ready_tx).instrument(span).await;
                });
                if let Err(e) = ready_rx.await {
                    error!(directive.id = id, "backlog manager failed to start: {}", e);
                    // if a backlog manager fails to start, we should exit rt
                    return;
                };
            }
            while set.join_next().await.is_some() {}
            info!("exiting directive manager runtime");
        });
    });
    Ok(h)
}

pub struct SpawnerOnDemandOption {
    pub directives: Vec<Directive>,
    pub id_rx: mpsc::Receiver<(u64, oneshot::Sender<()>)>,
    pub manager_option: Option<ManagerOpt>,
}

pub fn spawner_ondemand (
    ids: Vec<Arc<BacklogManagerId>>,
    opt: SpawnerOnDemandOption,
    rt: tokio::runtime::Handle,
) -> Result<thread::JoinHandle<()>> {
    let span = Span::current();
    let mgr_opt = opt.manager_option.clone().ok_or(anyhow!("missing manager option"))?;
    let mut cancel_rx = mgr_opt.cancel_tx.subscribe();
    info!(
        "starting spawner thread serving {} backlog managers",
        ids.len()
    ); 
    let h = thread::spawn(move || {
        let directives = opt.directives.clone();
        let mut id_rx = opt.id_rx;
        let _h = span.entered();
        let span = Span::current();
        rt.block_on(async move {           
            let mgr_opt = mgr_opt.clone();
            let _h = span.entered();
            let mut set = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_rx.recv() => {
                        break;
                    }
                    Some((id, tx)) = id_rx.recv() => {
                        let span = Span::current();
                        let _h = span.entered();
                        debug!(directive.id = id, "spawner received directive ID from filter");

                        // no need to check if the directive is in the cache, filter **only** sends one that isn't in there

                        // ids contains all directives and never change, so this should always succeed
                        let _ = ids.iter().filter(|i| i.id == id).take(1).last().map(|i| {
                            let span = Span::current();
                            debug!(directive.id = id, "spawner creating new backlog manager");
                            
                            let mut m = mgr_opt.clone();
                            m.backlog_option.directive = directives.iter().filter(|d| d.id == id).take(1).last().unwrap().to_owned();

                            // however, there is still period of time between:
                            // 1. a new backlog manager created below but hasn't insert its directive id into the cache yet before the filter receive another matching event
                            // 2. the existing backlog manager invalidating the cache and releasing the lock (which is a very short period of time)
                            //
                            // so here we need to check if there's really no existing backlog manager for this directive
                            // and arc is used because it's created/destructed at the same time as the backlog manager
                            // the same precaution is also taken inside the backlog manager start() fn, where it checks if the rx is locked
                            debug!("strong count of upstream_rx: {}", Arc::strong_count(&i.upstream_rx));
                            if Arc::strong_count(&i.upstream_rx) == 1 {
                                let rx = Arc::clone(&i.upstream_rx);
                                let b = BacklogManager::new(m, rx);
                                let (ready_tx, ready_rx) = oneshot::channel::<()>();
                                set.spawn(async move {
                                    let _detached = b.start(ready_tx).instrument(span).await;
                                });
                                
                                if !task::block_in_place(|| {
                                    if let Err(e) = ready_rx.blocking_recv() {
                                        error!(directive.id = id, "spawner failed to start backlog manager: {}", e);
                                        false
                                    } else {
                                        true                
                                    }
                                }) {
                                    return // exit closure without notifying filter. oneshot channel should then be closed and filter should recover
                                }
                            } else {
                                warn!(directive.id = id, "spawner found existing backlog manager still locking the receive channel, abort creating new one");
                            }
                            if let Err(e) = tx.send(()) {
                                // the filter should be able to recover
                                error!(directive.id = id, "spawner failed to notify filter that backlog manager is ready: {:?}", e);
                            };
                        });
                    }
                }
            }
            while set.join_next().await.is_some() {}
            info!("exiting directive manager runtime");
        });
    });
    Ok(h)
}


