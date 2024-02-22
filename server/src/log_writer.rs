use std::sync::Arc;

use crate::utils;
use anyhow::Result;
use tokio::{
    fs::{self, File, OpenOptions},
    io::AsyncWriteExt,
    sync::{broadcast, mpsc, RwLock},
};
use tracing::{error, info};

const ALARM_EVENT_LOG: &str = "siem_alarm_events.json";
const ALARM_LOG: &str = "siem_alarms.json";

pub struct LogWriter {
    alarm_file: Arc<RwLock<File>>,
    alarm_event_file: Arc<RwLock<File>>,
    pub sender: mpsc::Sender<LogWriterMessage>,
    receiver: mpsc::Receiver<LogWriterMessage>,
}

pub struct LogWriterMessage {
    pub data: String,
    pub file_type: FileType,
}

#[derive(PartialEq)]
pub enum FileType {
    Alarm,
    AlarmEvent,
}

impl LogWriter {
    pub async fn new(test_env: bool) -> Result<Self> {
        let log_dir = utils::log_dir(test_env)?;
        fs::create_dir_all(&log_dir).await?;
        let alarm_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join(ALARM_LOG))
            .await?;
        let alarm_event_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join(ALARM_EVENT_LOG))
            .await?;
        let (log_tx, log_rx) = mpsc::channel::<LogWriterMessage>(128);
        Ok(Self {
            alarm_file: Arc::new(RwLock::new(alarm_file)),
            alarm_event_file: Arc::new(RwLock::new(alarm_event_file)),
            sender: log_tx,
            receiver: log_rx,
        })
    }
    pub async fn write(&self, message: LogWriterMessage) -> Result<()> {
        let mut lock = match message.file_type {
            FileType::Alarm => self.alarm_file.write().await,
            FileType::AlarmEvent => self.alarm_event_file.write().await,
        };
        lock.write_all(message.data.as_bytes()).await?;
        Ok(())
    }

    pub async fn listener(&mut self, cancel_tx: broadcast::Sender<()>) -> Result<()> {
        let mut cancel_rx = cancel_tx.subscribe();
        loop {
            tokio::select! {
                _ = cancel_rx.recv() => {
                    info!("cancel signal received, exiting log writer thread");
                    break;
                },
                Some(msg) = self.receiver.recv() => {
                   // dont fail on log write error
                   self.write(msg)
                   .await
                   .map_err(|e| error!("log writer error: {}", e)).ok();
                },
            }
        }
        Ok(())
    }
}
