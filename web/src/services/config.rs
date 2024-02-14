use reqwasm::http::Request;
use serde::Deserialize;
use url::{ Url, Position };
use http_auth_basic::Credentials;

pub const DSIEM_CONFIG_URL: &str = "/config/dsiem_config.json";
pub const ES_CONFIG_URL: &str = "/ui/assets/config/esconfig.json";

#[derive(Deserialize, Clone, PartialEq)]
pub struct DsiemConfig {
    pub status: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Deserialize, Clone, PartialEq, Default)]
pub struct ESConfig {
    #[serde(rename(deserialize = "elasticsearch"))]
    pub search: String,
    #[serde(rename(deserialize = "kibana"))]
    pub dashboard: String,
}

#[derive(Deserialize, Clone, PartialEq, Default)]
pub struct SearchConfig {
    pub search: String,
    pub dashboard: String,
    pub auth_header: Option<String>,
}

pub async fn get_search_endpoints(dsiem_baseurl: String) -> Result<SearchConfig, String> {
    let url = dsiem_baseurl + ES_CONFIG_URL;
    let resp = Request::get(&url)
        .send().await
        .map_err(|e| "cannot read esconfig.json: ".to_owned() + &e.to_string())?;
    if resp.status() != 200 {
        return Err(format!("Server response: {} {}", resp.status(), resp.status_text()));
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let mut es_config: ESConfig = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    if !es_config.search.ends_with('/') {
        es_config.search += "/";
    }

    let u = Url::parse(&es_config.search).map_err(|e| e.to_string())?;
    let mut search_cfg = SearchConfig::default();
    if let Some(password) = u.password() {
        let username = u.username();
        if username.is_empty() || password.is_empty() {
            return Err("username and password cannot be empty if used in ES URL".to_owned());
        }
        let credentials = Credentials::new(username, password);
        let after = &u[Position::BeforeHost..];

        search_cfg.auth_header = Some(credentials.as_http_header());
        search_cfg.search = u.scheme().to_owned() + "://" + after;
    } else {
        search_cfg.search = es_config.search.clone();
    }

    if !es_config.dashboard.ends_with('/') {
        es_config.dashboard += "/";
    }
    search_cfg.dashboard = es_config.dashboard;

    Ok(search_cfg)
}

pub async fn read(dsiem_baseurl: String) -> Result<DsiemConfig, String> {
    let url = dsiem_baseurl + DSIEM_CONFIG_URL;
    let resp = Request::get(&url)
        .send().await
        .map_err(|e| "cannot load dsiem_config.json: ".to_owned() + &e.to_string())?;
    if resp.status() != 200 {
        return Err(format!("Elasticsearch response: {} {}", resp.status(), resp.status_text()));
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let config: DsiemConfig = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    Ok(config)
}
