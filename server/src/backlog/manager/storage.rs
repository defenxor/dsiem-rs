use std::sync::Arc;

use tokio::{
    fs::{self, create_dir_all, read_to_string, OpenOptions},
    io::AsyncWriteExt,
    sync::{mpsc, oneshot},
};
use tracing::{debug, info, warn};

use anyhow::Result;

use crate::{backlog::Backlog, utils};

pub fn load_with_spawner(test_env: bool, id_tx: mpsc::Sender<(u64, oneshot::Sender<()>)>) {
    // backlogs dir may not exist
    let ids = list(test_env).unwrap_or_default();
    debug!("found {} saved backlogs", ids.len());
    if !ids.is_empty() {
        info!(
            "found {} saved backlogs, instructing spawner to activate associated backlog managers",
            ids.len()
        );
        ids.iter().for_each(|id| {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            if let Err(e) = id_tx.blocking_send((*id, tx)) {
                warn!(directive.id = id, "failed to activate backlog manager so that it can to reload saved backlogs: {}", e);
            }
            debug!("waiting for spawner to acknowledge backlog manager activation");
            _ = rx.blocking_recv() // missing confirmation isn't critical here, spawner will have already reported the error
        });
    }
}

pub fn list(test_env: bool) -> Result<Vec<u64>> {
    let backlog_dir = utils::log_dir(test_env)?.join("backlogs");
    let mut res = vec![];
    let files = std::fs::read_dir(backlog_dir)?;
    files
        .filter_map(Result::ok)
        .filter(|d| {
            if let Some(e) = d.path().extension() {
                e == "json"
            } else {
                false
            }
        })
        .for_each(|f| {
            if let Ok(v) = f.file_name().into_string() {
                let s = v.replace(".json", "");
                if let Ok(id) = s.parse::<u64>() {
                    res.push(id);
                }
            }
        });
    Ok(res)
}

pub async fn load(test_env: bool, directive_id: u64) -> Result<Vec<Backlog>> {
    let backlog_dir = utils::log_dir(test_env)?.join("backlogs");
    let filename = backlog_dir.join(directive_id.to_string() + ".json");
    debug!(
        directive.id = directive_id,
        "loading {} (if it exist)",
        filename.to_string_lossy()
    );
    let s = read_to_string(filename.clone()).await?;
    // always remove the file if it exist, there could be content error in it
    _ = fs::remove_file(filename).await;
    let backlogs: Vec<Backlog> = serde_json::from_str(&s)?;
    Ok(backlogs)
}

pub async fn save(test_env: bool, directive_id: u64, source: Vec<Arc<Backlog>>) -> Result<()> {
    let backlog_dir = utils::log_dir(test_env)?.join("backlogs");
    create_dir_all(&backlog_dir).await?;
    let filename = directive_id.to_string() + ".json";
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(backlog_dir.join(filename))
        .await?;

    let mut backlogs = vec![];
    for b in source.into_iter() {
        let saveable = Backlog::saveable_version(b);

        // if extra sanity check for occurrence & stage are needed, they should be done here
        // currently such tests are only during loading in Backlog::runable_version()

        backlogs.push(saveable);
    }

    let s = serde_json::to_string_pretty(&backlogs)? + "\n";
    file.write_all(s.as_bytes()).await?;
    file.flush().await?;
    Ok(())
}
