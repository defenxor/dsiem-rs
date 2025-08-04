use std::{fs, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use atomic_counter::{AtomicCounter, RelaxedCounter};
use axum::{
    extract::{ConnectInfo, FromRequest, Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Router,
};
use axum_extra::response::ErasedJson; // this is just for pretty printing
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast::Sender;
use tower_http::{services::ServeDir, timeout::TimeoutLayer};
use tracing::{debug, error, info, info_span, trace, warn};

use crate::{eps_limiter::EpsLimiter, event::NormalizedEvent, tracer, utils};

mod app_error;
mod validate;

use app_error::AppError;

#[derive(Clone)]
pub struct AppState {
    pub conn_counter: Arc<RelaxedCounter>,
    pub eps_limiter: Arc<EpsLimiter>,
    pub test_env: bool,
    pub event_tx: tokio::sync::broadcast::Sender<NormalizedEvent>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigFile {
    filename: String,
}
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct ConfigFiles {
    files: Vec<ConfigFile>,
}

pub fn app(
    test_env: bool,
    writable_config: bool,
    eps_limiter: Arc<EpsLimiter>,
    event_tx: Sender<NormalizedEvent>,
) -> Result<Router> {
    let state = AppState { eps_limiter, test_env, conn_counter: Arc::new(RelaxedCounter::new(0)), event_tx };

    fn routes(state: AppState, writable: bool, web_dir: std::path::PathBuf) -> Router {
        let mut r = Router::new()
            .route("/events", post(events_handler))
            .route("/events/", post(events_handler))
            .route("/config", get(config_list_handler))
            .route("/config/", get(config_list_handler))
            .route("/config/:filename", get(config_download_handler));
        if writable {
            r = r
                .route("/config/:filename", post(config_upload_handler))
                .route("/config/:filename", delete(config_delete_handler));
        }
        r.with_state(state).nest_service("/ui", ServeDir::new(web_dir))
    }

    let web_dir = utils::web_dir(test_env)?;
    debug!("using web dir: {:?}", web_dir);
    let app = routes(state, writable_config, web_dir).layer(TimeoutLayer::new(Duration::from_secs(5)));
    Ok(app)
}

// create an extractor that internally uses `axum::Json` but has a custom
// rejection
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(AppError))]
pub struct JsonExtractor<T>(T);

pub async fn config_list_handler(State(state): State<AppState>) -> Result<ErasedJson, AppError> {
    let config_dir = (if state.test_env {
        utils::config_dir(state.test_env, Some(vec!["dl_config".to_owned()]))?
    } else {
        utils::config_dir(state.test_env, None)?
    })
    .to_string_lossy()
    .to_string();
    let mut cfg = ConfigFiles::default();

    let entries = std::fs::read_dir(config_dir.as_str())?;
    for element in entries {
        let path = element?.path();
        if let Some(extension) = path.extension() {
            if extension == "json" {
                if let Some(f) = path.file_name() {
                    cfg.files.push(ConfigFile { filename: f.to_string_lossy().to_string() });
                }
            }
        }
    }
    Ok(ErasedJson::pretty(cfg))
}

pub async fn config_download_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(cfg_file): Path<String>,
) -> Result<ErasedJson, AppError> {
    if !validate::validate_filename(cfg_file.as_str())? {
        warn!("l337 or epic fail attempt from {} detected. Discarding.", addr.to_string());
        return Err(AppError::new(
            StatusCode::IM_A_TEAPOT,
            "Not a valid filename, should be in any_N4m3-that_you_want.json format\n",
        ));
    }
    info!("request for file {} from {}", cfg_file, addr.to_string());

    let config_dir = (if state.test_env {
        utils::config_dir(state.test_env, Some(vec!["dl_config".to_owned()]))?
    } else {
        utils::config_dir(state.test_env, None)?
    })
    .to_string_lossy()
    .to_string();
    let file_path = std::path::Path::new(&config_dir).join(cfg_file);
    info!("reading file {}", file_path.to_string_lossy());
    let contents = fs::read_to_string(file_path)?;
    let val: Value = serde_json::from_str(&contents)?;
    Ok(ErasedJson::pretty(val))
}

pub async fn config_upload_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(cfg_file): Path<String>,
    JsonExtractor(payload): JsonExtractor<Value>,
) -> Result<StatusCode, AppError> {
    if !validate::validate_filename(&cfg_file)? {
        warn!("l337 or epic fail attempt from {} detected. Discarding.", addr.to_string());
        return Err(AppError::new(
            StatusCode::IM_A_TEAPOT,
            "Not a valid filename, should be in any_N4m3-that_you_want.json format\n",
        ));
    }
    if let Err(e) = validate::validate_content(&cfg_file, &payload) {
        warn!("l337 or epic fail attempt from {} detected. Discarding.", addr.to_string());
        let msg = format!("Invalid content detected, parsing error message is: {e}\n");
        return Err(AppError::new(StatusCode::IM_A_TEAPOT, &msg));
    }
    info!("Upload file request for {} from {}", cfg_file, addr.to_string());
    let config_dir = utils::config_dir(state.test_env, None)?.to_string_lossy().to_string();
    let file_path = std::path::Path::new(&config_dir).join(cfg_file.clone());
    info!("writing file {}", file_path.to_string_lossy());
    fs::write(file_path, serde_json::to_string_pretty(&payload)?)?;
    info!("file {} written successfully", cfg_file);
    Ok(StatusCode::CREATED)
}

pub async fn config_delete_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(cfg_file): Path<String>,
) -> Result<StatusCode, AppError> {
    if !validate::validate_filename(&cfg_file)? {
        warn!("l337 or epic fail attempt from {} detected. Discarding.", addr.to_string());
        return Err(AppError::new(
            StatusCode::IM_A_TEAPOT,
            "Not a valid filename, should be in any_N4m3-that_you_want.json format\n",
        ));
    }
    info!("Delete file request for {} from {}", cfg_file, addr.to_string());
    let config_dir = utils::config_dir(state.test_env, None)?.to_string_lossy().to_string();
    let file_path = std::path::Path::new(&config_dir).join(cfg_file.clone());
    fs::remove_file(file_path)?;
    info!("file {} deleted successfully", cfg_file);
    Ok(StatusCode::OK)
}

pub async fn events_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    JsonExtractor(value): JsonExtractor<Value>,
) -> Result<(), AppError> {
    let events = if !value.is_array() {
        let event: NormalizedEvent = serde_json::from_value(value).map_err(|e| {
            let s = e.to_string();
            error!("cannot read event, json parse error: {}", s);
            AppError::new(StatusCode::BAD_REQUEST, &s)
        })?;
        [event].to_vec()
    } else {
        serde_json::from_value(value).map_err(|e| {
            let s = e.to_string();
            error!("cannot read events, json parse error: {}", s);
            AppError::new(StatusCode::BAD_REQUEST, &s)
        })?
    };

    // println!("value: {}", serde_json::to_string_pretty(&value).unwrap());
    debug!("received {} events from {}", events.len(), addr.to_string());

    for mut event in events {
        if let Some(limiter) = &state.eps_limiter.as_ref().limiter {
            let limiter = limiter.read().await;
            debug!("max_tokens: {}, available: {}", limiter.max_tokens(), limiter.available());
            if limiter.try_wait().is_err() {
                return Err(AppError::new(StatusCode::TOO_MANY_REQUESTS, "EPS rate limit reached\n"));
            }
        }

        state.conn_counter.as_ref().inc();
        let conn_id = state.conn_counter.as_ref().get();
        event.conn_id = conn_id as u64;

        trace!("event received: {:?}", event);
        let span = info_span!("frontend handler", conn.id = conn_id, event.id);
        tracer::store_parent_into_event(&span, &mut event);

        if !event.valid() {
            warn!(event.id, "l337 or epic fail attempt from {} detected, discarding event", addr.to_string());
            return Err(AppError::new(StatusCode::IM_A_TEAPOT, "Invalid event\n"));
        }
        let now = Utc::now();
        if let Some(n) = now.timestamp_nanos_opt() {
            event.rcvd_time = n;
        }

        debug!(event.id, conn.id = event.conn_id, "sending event to nats");

        state
            .event_tx
            .send(event)
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, &format!("error sending to NATS: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::{
        body::Body,
        extract::connect_info::MockConnectInfo,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use serde_json::{json, Value};
    use tower::{Service, ServiceExt};
    use tracing_test::traced_test;

    use super::*; // for `call`, `oneshot`, and `ready`

    #[tokio::test]
    #[traced_test]
    async fn test_event_handler() {
        let eps_limiter = Arc::new(EpsLimiter::new(4, 4).unwrap());
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(5);
        let mut app = app(true, true, eps_limiter, event_tx)
            .unwrap()
            .layer(MockConnectInfo(SocketAddr::from(([1, 3, 3, 7], 666))))
            .into_service();

        // HTTP 500
        let b = Body::from(serde_json::to_vec(&json!({})).unwrap());
        let request = Request::builder()
            .uri("/events")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::BAD_REQUEST);

        let evt = json!({
            "event_id": "id1",
            "timestamp": "2023-01-01T00:00:00Z",
            "title": "foo",
            "sensor": "foo",
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.2",
        });
        let b = Body::from(serde_json::to_vec(&evt).unwrap());
        let request = Request::builder()
            .uri("/events")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::IM_A_TEAPOT); // missing plugin_id & plugin_sid

        let evt = json!({
            "event_id": "id2",
            "timestamp": "2023-01-01T00:00:00Z",
            "title": "foo",
            "plugin_id": 1001,
            "plugin_sid": 1,
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.2",
            "sensor": "foo",
        });

        tokio::spawn(async move {
            let _ = event_rx.recv().await;
        });

        let b = Body::from(serde_json::to_vec(&evt).unwrap());
        let request = Request::builder()
            .uri("/events")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::OK); // event accepted

        // test multiple events
        let events = Vec::from([evt.clone(), evt.clone()]);
        let b = Body::from(serde_json::to_vec(&events).unwrap());
        let request = Request::builder()
            .uri("/events")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::OK); // event accepted

        // test eps limiter

        let b = Body::from(serde_json::to_vec(&evt).unwrap());
        let request = Request::builder()
            .uri("/events")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::TOO_MANY_REQUESTS); // eps limit reached
    }

    #[tokio::test]
    #[traced_test]
    async fn test_config_handler() {
        let eps_limiter = Arc::new(EpsLimiter::new(0, 0).unwrap());
        let (event_tx, _) = tokio::sync::broadcast::channel(1);
        let mut app = app(true, true, eps_limiter, event_tx)
            .unwrap()
            .layer(MockConnectInfo(SocketAddr::from(([1, 3, 3, 7], 666))))
            .into_service();

        // 404
        let request = Request::builder().uri("/doesnt-exist").body(Body::empty()).unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::NOT_FOUND);

        // config list
        let request = Request::builder().uri("/config").body(Body::empty()).unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice::<Value>(&body).unwrap();
        let _config_files: ConfigFiles = serde_json::from_value(v).expect("fails to parse configfiles");
        assert!(!_config_files.files.is_empty());

        let request = Request::builder().uri("/config/").body(Body::empty()).unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::OK);

        // config download
        let request = Request::builder().uri("/config/backdoor.exe").body(Body::empty()).unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::IM_A_TEAPOT);

        let request = Request::builder().uri("/config/assets_testing.json").body(Body::empty()).unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::OK);

        // config upload

        let b = Body::from(serde_json::to_vec(&json!([1, 2, 3, 4])).unwrap());
        let request = Request::builder()
            .uri("/config/backdoor.exe")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::IM_A_TEAPOT); // filename rejected

        let b = Body::from(serde_json::to_vec(&json!([1, 2, 3, 4])).unwrap());
        let request = Request::builder()
            .uri("/config/assets_foo.json")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::IM_A_TEAPOT); // content rejected

        let assets = json!({
          "assets": [
            {
              "name": "Firewall",
              "cidr": "192.168.0.1/32",
              "value": 5
            }
          ]
        });
        let b = Body::from(serde_json::to_vec(&assets).unwrap());
        let request = Request::builder()
            .uri("/config/assets_foo.json")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::CREATED); // content accepted

        // config delete

        let request =
            Request::builder().uri("/config/malware.exe").method(http::Method::DELETE).body(Body::empty()).unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::IM_A_TEAPOT); // filename rejected

        let request =
            Request::builder().uri("/config/assets_foo.json").method(http::Method::DELETE).body(Body::empty()).unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::OK); // file deleted
    }
}
