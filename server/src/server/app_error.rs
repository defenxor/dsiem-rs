use axum::{ http::StatusCode, response::{ IntoResponse, Response } };
use tracing::error;

// Make our own error that wraps `anyhow::Error`.
pub struct AppError {
    err: Option<anyhow::Error>,
    status_code: StatusCode,
    resp_message: String,
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let Some(e) = &self.err {
            error!("Handler returned HTTP {} due to: {:?}", self.status_code, e);
        }
        (self.status_code, self.resp_message).into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AppError where E: Into<anyhow::Error> {
    // resp_message is empty because we don't want to leak any internal error messages to the client.
    fn from(err: E) -> Self {
        Self {
            err: Some(err.into()),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            resp_message: "".to_owned(),
        }
    }
}

impl AppError {
    pub fn new(status_code: StatusCode, message: &str) -> AppError {
        AppError {
            err: None,
            status_code,
            resp_message: message.to_owned(),
        }
    }
}
