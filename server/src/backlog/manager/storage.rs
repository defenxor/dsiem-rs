use std::sync::Arc;

use anyhow::Result;
use tokio::{
    fs::{self, create_dir_all, read_to_string, OpenOptions},
    io::AsyncWriteExt,
};
use tracing::debug;

use super::Backlog;
use crate::utils;

pub fn list(test_env: bool) -> Result<Vec<u64>> {
    let backlog_dir = utils::log_dir(test_env)?.join("backlogs");
    let ids = std::fs::read_dir(backlog_dir)?
        .filter_map(Result::ok)
        .filter(|d| d.path().extension().unwrap_or_default() == "json")
        .filter_map(|d| d.file_name().into_string().ok().map(|v| v.replace(".json", "")))
        .filter_map(|s| s.parse::<u64>().ok())
        .collect::<Vec<u64>>();
    Ok(ids)
}

pub async fn load(test_env: bool, directive_id: u64) -> Result<Vec<Backlog>> {
    let backlog_dir = utils::log_dir(test_env)?.join("backlogs");
    let filename = backlog_dir.join(directive_id.to_string() + ".json");
    debug!(directive.id = directive_id, "loading {} (if it exist)", filename.to_string_lossy());
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
    let mut file = OpenOptions::new().create(true).truncate(true).write(true).open(backlog_dir.join(filename)).await?;

    let mut backlogs = vec![];
    for b in source.into_iter() {
        let saveable = Backlog::saveable_version(b);

        // if extra sanity check for occurrence & stage are needed, they should be done
        // here currently such tests are only during loading in
        // Backlog::runable_version()

        backlogs.push(saveable);
    }

    let s = serde_json::to_string_pretty(&backlogs)? + "\n";
    file.write_all(s.as_bytes()).await?;
    file.flush().await?;
    Ok(())
}
