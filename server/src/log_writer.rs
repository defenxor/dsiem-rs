use std::{
    fmt::Display,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::Arc,
};

use anyhow::Result;
use parking_lot::Mutex;
use tracing::{error, info};

use crate::utils;

const ALARM_EVENT_LOG: &str = "siem_alarm_events.json";
const ALARM_LOG: &str = "siem_alarms.json";
const LOG_WRITER_BUFFER_SIZE: usize = 1024;

pub struct LogWriter {
    alarm_file: Arc<Mutex<File>>,
    alarm_event_file: Arc<Mutex<File>>,
    log_dir: PathBuf,
    pub receiver: crossbeam_channel::Receiver<LogWriterMessage>,
}

#[derive(Clone)]
pub struct LogWriterMessage {
    pub data: String,
    pub file_type: FileType,
}

#[derive(PartialEq, Clone)]
pub enum FileType {
    Alarm,
    AlarmEvent,
}

impl Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileType::Alarm => write!(f, "{}", ALARM_LOG),
            FileType::AlarmEvent => write!(f, "{}", ALARM_EVENT_LOG),
        }
    }
}

impl LogWriter {
    pub fn new(test_env: bool) -> Result<(Self, crossbeam_channel::Sender<LogWriterMessage>)> {
        let log_dir = utils::log_dir(test_env)?;
        let alarm_file = LogWriter::init_file(&log_dir, ALARM_LOG)?;
        let alarm_event_file = LogWriter::init_file(&log_dir, ALARM_EVENT_LOG)?;
        let (log_tx, log_rx) = crossbeam_channel::bounded::<LogWriterMessage>(LOG_WRITER_BUFFER_SIZE);
        Ok((Self { alarm_file, alarm_event_file, log_dir, receiver: log_rx }, log_tx))
    }

    fn init_file(dir: &PathBuf, path: &str) -> Result<Arc<Mutex<File>>> {
        fs::create_dir_all(dir)?;
        let file = OpenOptions::new().create(true).append(true).open(dir.join(path))?;
        Ok(Arc::new(Mutex::new(file)))
    }

    fn write(&self, message: &LogWriterMessage) -> Result<()> {
        let mut lock = match message.file_type {
            FileType::Alarm => self.alarm_file.lock(),
            FileType::AlarmEvent => self.alarm_event_file.lock(),
        };
        if lock.metadata()?.nlink() == 0 {
            return Err(anyhow::anyhow!("missing file {}", message.file_type));
        }
        lock.write_all(message.data.as_bytes())?;
        lock.flush()?;
        Ok(())
    }

    pub fn listener(&mut self) -> Result<()> {
        loop {
            let msg = self.receiver.recv().map_err(|e| {
                info!("exiting log writer thread");
                e
            })?;
            if let Err(e) = self.write(&msg) {
                error!("log writer error: {}, will try to re-create/open it", e);
                let file = LogWriter::init_file(&self.log_dir, &msg.file_type.to_string()).map_err(|e| {
                    error!("cannot initialize {}: {}", &msg.file_type, e);
                    e
                })?;
                match msg.file_type {
                    FileType::AlarmEvent => {
                        self.alarm_event_file = file.clone();
                    }
                    FileType::Alarm => {
                        self.alarm_file = file.clone();
                    }
                }
            }
        }
    }
}

#[cfg(test)]

mod tests {
    use std::{io::Read, thread, time::Duration};

    use super::*;

    #[test]
    fn test_log_writer() {
        let data = "meivosh8aThua2aefiu5ci3Nohkeew".to_string();
        let (mut writer, sender) = LogWriter::new(true).unwrap();

        _ = thread::spawn(move || {
            _ = writer.listener();
        });

        sender.send(LogWriterMessage { file_type: FileType::Alarm, data: data.clone() }).unwrap();

        thread::sleep(Duration::from_secs(1));
        let log_dir = utils::log_dir(true).unwrap();
        let mut alarm_file = OpenOptions::new().read(true).open(log_dir.join(ALARM_LOG)).unwrap();
        let mut res = String::new();
        alarm_file.read_to_string(&mut res).unwrap();
        assert!(res.contains(&data));
    }
}
