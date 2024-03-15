use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    sync::Arc,
};

use crate::utils;
use anyhow::Result;
use parking_lot::Mutex;
use tracing::{error, info};

const ALARM_EVENT_LOG: &str = "siem_alarm_events.json";
const ALARM_LOG: &str = "siem_alarms.json";

pub struct LogWriter {
    alarm_file: Arc<Mutex<File>>,
    alarm_event_file: Arc<Mutex<File>>,
    pub sender: crossbeam_channel::Sender<LogWriterMessage>,
    pub receiver: crossbeam_channel::Receiver<LogWriterMessage>,
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
    pub fn new(test_env: bool) -> Result<Self> {
        let log_dir = utils::log_dir(test_env)?;
        fs::create_dir_all(&log_dir)?;
        let alarm_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join(ALARM_LOG))?;
        let alarm_event_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join(ALARM_EVENT_LOG))?;
        let (log_tx, log_rx) = crossbeam_channel::bounded::<LogWriterMessage>(1024);
        Ok(Self {
            alarm_file: Arc::new(Mutex::new(alarm_file)),
            alarm_event_file: Arc::new(Mutex::new(alarm_event_file)),
            sender: log_tx,
            receiver: log_rx,
        })
    }
    fn write(&self, message: LogWriterMessage) -> Result<()> {
        let mut lock = match message.file_type {
            FileType::Alarm => self.alarm_file.lock(),
            FileType::AlarmEvent => self.alarm_event_file.lock(),
        };
        lock.write_all(message.data.as_bytes())?;
        Ok(())
    }

    pub fn listener(&mut self) -> Result<()> {
        loop {
            match self.receiver.recv() {
                Ok(msg) => {
                    // dont fail on log write error
                    self.write(msg)
                        .map_err(|e| error!("log writer error: {}", e))
                        .ok();
                }
                Err(_) => {
                    info!("exiting log writer listener");
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]

mod tests {
    use std::{io::Read, thread};

    use tracing_test::traced_test;

    use super::*;

    #[test]
    #[traced_test]
    fn test_log_writer() {
        let data = "meivosh8aThua2aefiu5ci3Nohkeew".to_string();
        let mut writer = LogWriter::new(true).unwrap();
        let sender = writer.sender.clone();
        _ = thread::spawn(move || {
            _ = writer.listener();
        });

        sender
            .send(LogWriterMessage {
                file_type: FileType::Alarm,
                data: data.clone(),
            })
            .unwrap();

        let log_dir = utils::log_dir(true).unwrap();
        let mut alarm_file = OpenOptions::new()
            .read(true)
            .open(log_dir.join(ALARM_LOG))
            .unwrap();
        let mut res = String::new();
        alarm_file.read_to_string(&mut res).unwrap();
        assert!(res.contains(&data));
    }
}
