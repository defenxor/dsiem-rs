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
use tracing::{error, info, warn};

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
        Ok(())
    }

    pub fn listener(&mut self) -> Result<()> {
        loop {
            let msg = self.receiver.recv().map_err(|e| {
                info!("exiting log writer thread");
                e
            })?;
            if let Err(e) = self.write(&msg) {
                // this also happens on first time file creation, so not always unexpected
                warn!("log writer error: {}, will try to re-create/open it", e);
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
                if let Err(e) = self.write(&msg) {
                    error!("log writer: skipping entry, still can't write to {}: {}", msg.file_type, e);
                }
            }
        }
    }
}

#[cfg(test)]

mod tests {
    use std::{io::Read, thread, time::Duration};

    use tracing::Span;
    use tracing_test::traced_test;

    use super::*;

    #[test]
    #[traced_test]
    fn test_log_writer() {
        let log_dir = utils::log_dir(true).unwrap();

        let clean_up = || {
            for file_name in [ALARM_LOG, ALARM_EVENT_LOG] {
                let file_path = log_dir.join(file_name);
                _ = fs::remove_file(&file_path);
            }
        };
        clean_up();

        let data = "meivosh8aThua2aefiu5ci3Nohkeew".to_string();
        let (mut writer, sender) = LogWriter::new(true).unwrap();

        let span = Span::current();
        _ = thread::spawn(move || {
            let _guard = span.entered();
            _ = writer.listener();
        });

        for (file_type, file_name) in [(FileType::Alarm, ALARM_LOG), (FileType::AlarmEvent, ALARM_EVENT_LOG)] {
            let msg = LogWriterMessage { file_type, data: data.clone() };

            let file_path = log_dir.join(file_name);
            info!("testing using file: {:?}", file_path);

            // send a message and verify content is written to file
            sender.send(msg.clone()).unwrap();
            thread::sleep(Duration::from_millis(500));

            let mut file = OpenOptions::new().read(true).open(&file_path).unwrap();
            let mut res = String::new();
            file.read_to_string(&mut res).unwrap();
            assert!(res.contains(&data));

            // simulate file deletion, should be re-created
            fs::remove_file(log_dir.join(file_name)).unwrap();
            sender.send(msg.clone()).unwrap();
            thread::sleep(Duration::from_millis(500));

            let res = OpenOptions::new().read(true).open(&file_path);
            assert!(res.is_ok());

            let expected = format!("log writer error: missing file {}", file_name);
            logs_assert(|lines: &[&str]| match lines.iter().filter(|line| line.contains(&expected)).count() {
                1 => Ok(()),
                n => Err(format!("Expected 1 matching logs, but found {}", n)),
            });

            /*
                # simulate inaccessible file, doesn't work because writer still has the file open
                # with prev permissions

                let mut perms = fs::metadata(&file_path).unwrap().permissions();
                perms.set_readonly(true);
                fs::set_permissions(&file_path, perms).unwrap();

                info!("writing to read-only file {:?}", file_path);
                sender.send(msg.clone()).unwrap();
                logs_contain("cannot initialize");
            */
        }

        clean_up();
    }
}
