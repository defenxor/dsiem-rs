use std::{ fs::File, io::Write };
use std::str;

use crate::utils;
use serde::Deserialize;
use serde_derive::Serialize;
use tracing::debug;
use anyhow::{ Result, Context };

#[derive(Deserialize)]
struct ConfigFile {
    filename: String,
}
#[derive(Deserialize)]
struct ConfigFiles {
    files: Vec<ConfigFile>,
}

#[derive(Serialize)]
pub struct DsiemConfig {
    pub status: Vec<String>,
    pub tags: Vec<String>,
}

pub fn write_dsiem_config(test_env: bool, status: Vec<String>, tags: Vec<String>) -> Result<()> {
    let config_dir = if test_env {
        utils::config_dir(test_env, Some(vec!["dl_config".to_owned()]))?
    } else {
        utils::config_dir(test_env, None)?
    };
    let path = config_dir.to_string_lossy().to_string() + "/dsiem_config.json";
    let mut local = File::create(&path).context(
        format!("cannot create dsiem config file {}", path)
    )?;
    let c = DsiemConfig {
        status,
        tags,
    };
    let content = serde_json::to_string_pretty(&c)?;
    local.write_all(content.as_bytes()).context("cannot write file")?;
    Ok(())
}

async fn list_config_files(frontend_url: String) -> Result<Vec<ConfigFile>> {
    debug!("listing config files from {}", frontend_url);
    let resp = reqwest
        ::get(frontend_url.clone() + "/config/").await
        .context("cannot get a list of config files from frontend")?;
    let text = resp.text().await.context("cannot parse response for request to list config files")?;
    let c: ConfigFiles = serde_json
        ::from_str(&text)
        .context("cannot parse response for request to list config files. text: {}")?;
    debug!("found {} config files", c.files.len());
    Ok(c.files)
}

pub async fn download_files(
    test_env: bool,
    subdir: Option<Vec<String>>,
    frontend_url: String,
    node_name: String
) -> Result<()> {
    let config_dir = utils::config_dir(test_env, subdir)?.to_string_lossy().to_string();
    let files = list_config_files(frontend_url.clone()).await?;
    for f in files
        .into_iter()
        .filter(
            |f|
                f.filename.starts_with("assets_") ||
                f.filename.starts_with("intel_") ||
                f.filename.starts_with("vuln_") ||
                f.filename.starts_with(&format!("directives_{}", node_name.clone()))
        ) {
        let url = frontend_url.clone() + "/config/" + &f.filename;
        debug!("downloading config file {}", url.clone());
        let resp = reqwest::get(url.clone()).await?;
        let content = resp.text().await?;
        let path = config_dir.clone() + "/" + &f.filename;
        let mut local = File::create(&path).context(format!("cannot create config file {}", path))?;
        local.write_all(content.as_bytes()).context("cannot write file")?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use tokio::join;
    use tracing_test::traced_test;

    use super::*;
    #[tokio::test]
    #[traced_test]
    async fn test_config() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        debug!("using url: {}", url.clone());
        tokio::spawn(async move {
            let _m1 = server.mock("GET", "/config/").with_status(418).create_async().await;
        });

        let res = list_config_files(url).await;
        assert!(res.is_err());

        let file_list =
            r#"{ 
                "files" : [
                  {"filename" : "assets_foo.json"},
                  {"filename" : "intel_bar.json"},
                  {"filename" : "vuln_baz.json"}
                ] 
            }"#;

        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        debug!("using url: {}", url.clone());

        let _m1 = server
            .mock("GET", "/config/")
            .with_status(200)
            .with_body(file_list)
            .create_async();
        let _m2 = server
            .mock("GET", "/config/assets_foo.json")
            .with_status(200)
            .with_body("{}")
            .create_async();
        let _m3 = server
            .mock("GET", "/config/intel_bar.json")
            .with_status(200)
            .with_body("{}")
            .create_async();
        let _m4 = server
            .mock("GET", "/config/vuln_baz.json")
            .with_status(200)
            .with_body("{}")
            .create_async();
        join!(_m1, _m2, _m3, _m4);

        let config_files = list_config_files(url.clone()).await;
        if let Err(e) = config_files {
            panic!("error: {}", e);
        }
        let config_files = config_files.unwrap();
        assert!(config_files.len() == 3);
        assert!(logs_contain("listing config files from"));
        let res = download_files(
            true,
            Some(vec!["dl_config".to_owned()]),
            url,
            "qux".to_owned()
        ).await;
        assert!(res.is_ok());
    }
}
