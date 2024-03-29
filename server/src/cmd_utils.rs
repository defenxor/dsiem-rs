use std::time::Duration;

use anyhow::{anyhow, Error, Result};
use tokio::sync::broadcast;
use tracing::{error, info};

use crate::{
    allocator::{calculate, ThreadAllocation},
    backlog::manager::{OpLoadParameter, QueueMode},
    messenger::UNBOUNDED_QUEUE_SIZE,
    tracer,
};

const DEADLOCK_TIMEOUT_IN_SECONDS: u64 = 10;

pub fn log_startup_err(context: &str, err: Error) -> Error {
    _ = tracing_subscriber::fmt().try_init();
    error!("error {}: {:?}", context, err);
    err
}

pub fn ctrlc_handler(cancel_tx: broadcast::Sender<()>, report_err: bool) -> Result<()> {
    let res = ctrlc::set_handler(move || {
        info!("termination signal received, shutting down ...");
        let _ = cancel_tx.send(());
    });
    if let Err(e) = res {
        if report_err {
            return Err(e.into());
        }
    }
    Ok(())
}

pub struct Validator {}

impl Validator {
    pub fn log_verbosity(trace: bool, debug: bool, verbosity: u8) -> u8 {
        if debug {
            1
        } else if trace {
            2
        } else {
            verbosity
        }
    }
    pub fn max_queue(max_queue: usize) -> usize {
        if max_queue == 0 {
            UNBOUNDED_QUEUE_SIZE
        } else {
            max_queue
        }
    }
    pub fn log_format(use_json: bool) -> tracer::LogType {
        if use_json {
            tracer::LogType::Json
        } else {
            tracer::LogType::Plain
        }
    }
    pub fn thread_allocation(
        num_of_directives: usize,
        max_eps: u32,
        filter_threads: usize,
    ) -> Result<ThreadAllocation> {
        calculate(
            num_of_directives,
            max_eps as usize,
            if filter_threads == 0 { None } else { Some(filter_threads) },
            None,
        )
    }
    pub fn verify_risk_boundaries(min: u8, max: u8) -> Result<()> {
        if min < 2 || max > 9 || min == max {
            return Err(anyhow!("invalid value provided"));
        }
        Ok(())
    }
    pub fn verify_dirs_idle_timeout_minutes(t: u16) -> Result<()> {
        if t < 5 {
            return Err(anyhow!("invalid value provided, minimum is 5 minutes"));
        }
        Ok(())
    }

    pub fn load_param(max_queue: usize, max_eps: u32) -> OpLoadParameter {
        match max_queue {
            0 | UNBOUNDED_QUEUE_SIZE => OpLoadParameter {
                limit_cap: UNBOUNDED_QUEUE_SIZE,
                max_wait: Duration::from_secs(DEADLOCK_TIMEOUT_IN_SECONDS),
                queue_mode: QueueMode::Unbounded,
            },
            _ => OpLoadParameter {
                limit_cap: max_queue * 9 / 10, // 90% of max_queue
                max_wait: Duration::from_millis((1000 / max_eps).into()),
                queue_mode: QueueMode::Bounded,
            },
        }
    }

    // we take in unsigned values from CLI to make sure there's no negative numbers,
    // and convert them to signed value required by timestamp related APIs.
    pub fn max_delay(max_delay: u16) -> Result<i64> {
        chrono::Duration::try_seconds(max_delay.into())
            .and_then(|d| d.num_nanoseconds())
            .ok_or_else(|| anyhow!("invalid value provided"))
    }

    // this cannot fail, clap already ensures the value is within the range of u16
    // (0-65535)
    pub fn min_alarm_lifetime(min_alarm_lifetime: u16) -> i64 {
        chrono::Duration::try_minutes(min_alarm_lifetime.into()).unwrap_or_default().num_seconds()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{cmd_utils::Validator as v, tracer};

    #[test]
    fn test_validator() {
        assert!(v::log_format(true) == tracer::LogType::Json);
        assert!(v::log_format(false) == tracer::LogType::Plain);

        assert!(v::max_queue(0) == UNBOUNDED_QUEUE_SIZE);
        assert!(v::max_queue(1) == 1);

        assert!(v::load_param(0, 100).limit_cap == UNBOUNDED_QUEUE_SIZE);
        assert!(v::load_param(UNBOUNDED_QUEUE_SIZE, 100).limit_cap == UNBOUNDED_QUEUE_SIZE);
        assert!(v::load_param(0, 100).queue_mode == QueueMode::Unbounded);
        assert!(v::load_param(100, 100).limit_cap == 90);
        assert!(v::load_param(100, 100).queue_mode == QueueMode::Bounded);

        assert!(v::thread_allocation(10, 100, 0).is_ok());
        assert!(v::thread_allocation(10, 100, 1).is_ok());

        for i in 0..4 {
            for debug in [false, true].iter() {
                for trace in [false, true].iter() {
                    let expected = if *debug {
                        1
                    } else if *trace {
                        2
                    } else {
                        i
                    };
                    assert!(v::log_verbosity(*trace, *debug, i) == expected);
                }
            }
        }
    }
}
