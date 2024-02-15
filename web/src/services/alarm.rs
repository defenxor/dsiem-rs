use reqwasm::http::Request;
use serde::{ Deserialize, Serialize };
use serde_json::Value;
use gloo_console::warn;
use chrono::prelude::*;

use super::config::{ self, SearchConfig };

const INDEX_ALARM_EVENT: &str = "siem_alarm_events-*";
const INDEX_ALARM: &str = "siem_alarms";
const INDEX_EVENT: &str = "siem_events-*";

pub const MAX_EVENTS: usize = 500;
const DEFAULT_ES_MAX_SIZE: i32 = 10000;

#[derive(Default, Deserialize, Clone, PartialEq)]
#[derive(Debug, Eq, Ord, PartialOrd)]
pub struct Rules {
    pub stage: u8,
    pub timeout: u16,
    pub name: String,
    pub protocol: String,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub status: String,
    pub port_from: String,
    pub port_to: String,
    pub plugin_id: u64,
    #[serde(default)]
    pub start_time: u64,
    #[serde(default)]
    pub end_time: u64,
    pub reliability: u8,
    pub plugin_sid: Vec<u64>,
    pub occurrence: u64,
    #[serde(default)]
    pub ttl_matched: u64,
}

#[derive(Default, Deserialize, Clone, PartialEq)]
pub struct IntelVulnerabilities {
    pub provider: String,
    pub result: String,
    pub term: String,
}

#[derive(Default, Deserialize, Clone, PartialEq)]
pub struct CustomData {
    pub label: String,
    pub content: String,
}

#[derive(Deserialize, Clone, PartialEq)]
pub struct Alarm {
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub id: String,
    pub title: String,
    pub status: String,
    #[serde(default)]
    pub custom_data: Vec<CustomData>,
    pub kingdom: String,
    pub category: String,
    pub updated_time: DateTime<Utc>,
    pub risk: u8,
    pub risk_class: String,
    pub src_ips: Vec<String>,
    pub dst_ips: Vec<String>,
    pub networks: Vec<String>,
    pub rules: Vec<Rules>,
    pub tag: String,
    #[serde(default)]
    pub intel_hits: Vec<IntelVulnerabilities>,
    #[serde(default)]
    pub vulnerabilities: Vec<IntelVulnerabilities>,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default)]
    pub tag_selection: Vec<String>,
    #[serde(default)]
    pub status_selection: Vec<String>,
    pub perm_index: String,
    #[serde(default)]
    pub search_config: config::SearchConfig,
    #[serde(default)]
    pub max_events_reached: bool,
}

#[derive(Deserialize, Clone)]
pub struct AlarmEvent {
    pub alarm_id: String,
    pub event_id: String,
    pub stage: u8,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct AlarmEvents {
    #[serde(rename(deserialize = "_source"))]
    #[serde(skip_serializing)]
    pub source: AlarmEvent,
    #[serde(rename(deserialize = "_index", serialize = "_index"))]
    pub index: String,
    #[serde(rename(deserialize = "_id", serialize = "_id"))]
    pub id: String,
}

#[derive(Deserialize, Clone, PartialEq)]
pub struct Event {
    pub timestamp: DateTime<Utc>,
    pub event_id: String,
    pub title: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    #[serde(default)]
    pub src_port: u16,
    #[serde(default)]
    pub dst_port: u16,
    pub sensor: String,
    pub plugin_id: u64,
    pub plugin_sid: u64,
    #[serde(default)]
    pub stage: u8,
}

pub async fn update_field(
    search_cfg: &SearchConfig,
    index: String,
    id: String,
    field: String,
    value: String
) -> Result<String, String> {
    let url = search_cfg.search.clone() + &index + "/_update/" + &id;
    let data = r#"{ "doc": { ""#.to_owned() + &field + r#"": ""# + &value + r#"" } }"#;

    let mut req = Request::post(url.as_str()).body(data).header("Content-Type", "application/json");
    if let Some(auth) = &search_cfg.auth_header {
        req = req.header("Authorization", auth.as_str());
    }

    let resp = req.send().await.map_err(|e| e.to_string())?;

    let body = resp.text().await.map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(body.as_str()).map_err(|e| e.to_string())?;
    if v["error"].as_null().is_none() {
        return Err(v["error"]["reason"].to_string());
    }
    let res = v["result"].to_string();
    Ok(res)
}

pub async fn delete_alarm(search_cfg: &SearchConfig, id: String) -> Result<String, String> {
    // first siem_alarm_events, using _bulk API
    let alarm_events = get_alarm_event(search_cfg, &id).await?;
    let mut delete_data = "".to_string();
    for ae in alarm_events.into_iter() {
        let str = serde_json::to_string(&ae).unwrap();
        delete_data = delete_data + r#"{ "delete" : "# + &str + r#"}"# + "\n";
    }
    let url = search_cfg.search.clone() + INDEX_ALARM_EVENT + "/_bulk";

    let mut req = Request::post(url.as_str())
        .body(delete_data)
        .header("Content-Type", "application/json");
    if let Some(auth) = &search_cfg.auth_header {
        req = req.header("Authorization", auth.as_str());
    }

    _ = req.send().await.map_err(|e| e.to_string())?;

    // next for siem_alarms
    // curl -XPOST -H 'content-type:application/json' 'localhost:9200/siem_alarms/_delete_by_query' -d'{"query": { "match" : { "_id": "7deNuzN2k" } } }'

    let url = search_cfg.search.clone() + INDEX_ALARM + "/_delete_by_query?refresh=true";
    let data = r#"{ "query": { "match": { "_id": ""#.to_owned() + &id + r#"" } } }"#;

    let mut req = Request::post(url.as_str()).body(data).header("Content-Type", "application/json");
    if let Some(auth) = &search_cfg.auth_header {
        req = req.header("Authorization", auth.as_str());
    }

    let resp = req.send().await.map_err(|e| e.to_string())?;

    let body = resp.text().await.map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(body.as_str()).map_err(|e| e.to_string())?;
    if let Some(n) = v["deleted"].as_u64() {
        if n > 0 {
            return Ok("deleted".to_string());
        }
    }
    Err("alarm not found".to_owned())
}

pub async fn read(dsiem_baseurl: String, id: String) -> Result<Alarm, String> {
    let config = super::config::read(dsiem_baseurl.clone()).await?;
    let search_config = super::config::get_search_endpoints(dsiem_baseurl).await?;
    let mut alarm = get_alarm(&search_config, &id).await?;
    alarm.search_config = search_config.clone();
    alarm.status_selection = config.status;
    alarm.tag_selection = config.tags;
    let alarm_events = get_alarm_event(&search_config, &id).await?;

    let mut counter = 0;
    alarm.rules.sort_by(|a, b| a.stage.cmp(&b.stage));

    for r in alarm.rules.iter_mut() {
        for ae in alarm_events.iter() {
            if r.stage == ae.source.stage {
                r.ttl_matched += 1;

                if counter == MAX_EVENTS {
                    continue;
                }
                let res = get_event(&search_config, &ae.source.event_id).await;
                if res.is_err() {
                    warn!("skipping missing event ", &ae.source.event_id);
                    continue;
                }
                let mut event = res.unwrap();
                event.stage = ae.source.stage;
                alarm.events.push(event);
                counter += 1;
            }
        }
    }

    if alarm.events.len() == MAX_EVENTS {
        alarm.max_events_reached = true;
    }

    for r in alarm.rules.iter_mut() {
        if r.status.is_empty() && r.start_time > 0 {
            r.status = "active".to_string();
        } else if r.status.is_empty() && r.start_time == 0 {
            r.status = "inactive".to_string();
        }
    }
    alarm.id = id;
    Ok(alarm)
}

async fn get_alarm_event(
    search_cfg: &SearchConfig,
    alarm_id: &String
) -> Result<Vec<AlarmEvents>, String> {
    let url =
        search_cfg.search.to_string() +
        INDEX_ALARM_EVENT +
        "/_search?size=" +
        DEFAULT_ES_MAX_SIZE.to_string().as_str();

    let data =
        r#"{ "query": { "term": { "alarm_id.keyword": ""#.to_owned() + alarm_id + r#"" }  } }"#;

    let mut req = Request::post(url.as_str()).body(data).header("Content-Type", "application/json");
    if let Some(auth) = &search_cfg.auth_header {
        req = req.header("Authorization", auth.as_str());
    }

    let resp = req.send().await.map_err(|e| e.to_string())?;
    if resp.status() != 200 {
        return Err(format!("Elasticsearch response: {} {}", resp.status(), resp.status_text()));
    }

    let body = resp.text().await.map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(body.as_str()).map_err(|e| e.to_string())?;
    let hits = v["hits"]["hits"].to_string();
    let alarm_events: Vec<AlarmEvents> = serde_json::from_str(&hits).map_err(|e| e.to_string())?;

    Ok(alarm_events)
}

async fn get_alarm(search_cfg: &SearchConfig, id: &String) -> Result<Alarm, String> {
    let url = search_cfg.search.to_string() + INDEX_ALARM + "/_search";
    // curl 'localhost:9200/siem_alarms-*/_search' -XPOST -H 'content-type:application/json' -d'{ "query": { "term" : { "_id": "gUJis6htM" } } }'

    let data = r#"{ "query": { "term": { "_id": ""#.to_owned() + id + r#"" }  } }"#;

    let mut req = Request::post(url.as_str()).body(data).header("Content-Type", "application/json");
    if let Some(auth) = &search_cfg.auth_header {
        req = req.header("Authorization", auth.as_str());
    }

    let resp = req.send().await.map_err(|e| e.to_string())?;
    if resp.status() != 200 {
        return Err(format!("Elasticsearch response: {} {}", resp.status(), resp.status_text()));
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(body.as_str()).map_err(|e| e.to_string())?;
    let source = v["hits"]["hits"][0]["_source"].to_string();
    if source == "null" {
        return Err("search returned no hit".to_owned());
    }
    let alarm: Alarm = serde_json
        ::from_str(&source)
        .map_err(|e| "cannot deserialize alarm: ".to_owned() + &e.to_string())?;
    Ok(alarm)
}

async fn get_event(search_cfg: &SearchConfig, id: &String) -> Result<Event, String> {
    let url = search_cfg.search.to_string() + INDEX_EVENT + "/_search";

    let data = r#"{ "query": { "term": { "event_id.keyword": ""#.to_owned() + id + r#"" }  } }"#;

    let mut req = Request::post(url.as_str()).body(data).header("Content-Type", "application/json");
    if let Some(auth) = &search_cfg.auth_header {
        req = req.header("Authorization", auth.as_str());
    }

    let resp = req.send().await.map_err(|e| e.to_string())?;
    if resp.status() != 200 {
        return Err(format!("Elasticsearch response: {} {}", resp.status(), resp.status_text()));
    }

    let body = resp.text().await.map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(body.as_str()).map_err(|e| e.to_string())?;
    let source = v["hits"]["hits"][0]["_source"].to_string();
    let event: Event = serde_json::from_str(&source).map_err(|e| e.to_string())?;
    Ok(event)
}
