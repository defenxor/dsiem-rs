use std::{sync::Arc, thread};

use mini_moka::sync::Cache;
use tokio::{sync::{broadcast, mpsc, oneshot, Mutex}, task};
use tracing::{debug, error, info, warn, Instrument, Span};

use crate::{directive::Directive, event::NormalizedEvent, log_writer::LogWriterMessage, manager::ManagerOpt};

use super::manager::{BacklogManager, OpLoadParameter};


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
    OnDemand(Vec<Arc<BacklogManagerId>>),
    All(Vec<BacklogManager>),
}

pub struct SpawnerOnDemandOption {
    pub directives: Vec<Directive>,
    pub tokio_handle: tokio::runtime::Handle,
    pub cancel_tx: broadcast::Sender<()>,
    pub id_rx: mpsc::Receiver<(u64, oneshot::Sender<()>)>,
    pub load_param: OpLoadParameter,
    pub log_tx: crossbeam_channel::Sender<LogWriterMessage>,
    pub report_interval: u64,
}

pub fn spawner(dir_managers: Vec<BacklogManager>, rt: tokio::runtime::Handle) -> thread::JoinHandle<()> {
  let span = Span::current();
  thread::spawn(move || {
      let _h = span.entered();
      let span = Span::current();
      rt.block_on(async move {
          let _h = span.entered();
          let mut set: task::JoinSet<_> = tokio::task::JoinSet::new();
          for dir_manager in dir_managers {
              let span = Span::current();
              let (ready_tx, ready_rx) = oneshot::channel::<()>();
              let id = dir_manager.directive.id;
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
  })
}

pub fn spawner_ondemand(
  ids: Vec<Arc<BacklogManagerId>>,
  opt: SpawnerOnDemandOption,
  manager_opt: ManagerOpt
) -> thread::JoinHandle<()> {
  let span = Span::current();
  let mut cancel_rx = manager_opt.cancel_tx.subscribe();
  let mut id_rx = opt.id_rx;
  info!(
      "starting spawner thread serving {} backlog managers",
      ids.len()
  );
  
  thread::spawn(move || {
      let _h = span.entered();
      let span = Span::current();
      opt.tokio_handle.block_on(async move {
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
                          
                          let directive = opt.directives.iter().filter(|d| d.id == id).take(1).last().unwrap().to_owned();

                          // however, there is still period of time between:
                          // 1. a new backlog manager created below but hasn't insert its directive id into the cache yet before the filter receive another matching event
                          // 2. the existing backlog manager invalidating the cache and releasing the lock (which is a very short period of time)
                          //
                          // so here we need to check if there's really no existing backlog manager for this directive
                          // and arc is used because it's created/destructed at the same time as the backlog manager
                          // the same precaution is also taken inside the backlog manager start() fn, where it checks if the rx is locked
                          if Arc::strong_count(&i.upstream_rx) == 1 {
                              let rx = Arc::clone(&i.upstream_rx);
                              let b = BacklogManager::new(
                                  &manager_opt,
                                  directive,
                                  &opt.load_param,
                                  &opt.log_tx,
                                  &opt.report_interval,
                                  rx,
                              );
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
  })
}
