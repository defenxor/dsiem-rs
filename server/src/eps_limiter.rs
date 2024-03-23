use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use ratelimit::Ratelimiter;
use tokio::{
    sync::{broadcast::Sender, RwLock},
    time::interval,
};
use tracing::{debug, info};
const EPS_ADJUSTMENT_INTERVAL_IN_SECONDS: u64 = 5;

pub struct EpsLimiter {
    max_eps: u64,
    min_eps: u64,
    pub limiter: Option<Arc<RwLock<Ratelimiter>>>,
    overload: Arc<RwLock<bool>>,
}

impl EpsLimiter {
    pub async fn start(&self, cancel_tx: Sender<()>, mut bp_rx: tokio::sync::mpsc::Receiver<bool>) -> Result<()> {
        let mut modifier = interval(Duration::from_secs(EPS_ADJUSTMENT_INTERVAL_IN_SECONDS));
        let mut cancel_rx = cancel_tx.subscribe();
        debug!("starting EPS limiter thread");
        loop {
            tokio::select! {
                Some(overload) = bp_rx.recv() => {
                    let mut l = self.overload.write().await;
                    *l = overload;
                }
                _ = cancel_rx.recv() => {
                        info!("cancel signal received, exiting EPS limiter thread");
                        break;
                    }
                _ = modifier.tick() => {
                    let overload = self.overload.read().await;
                    let current = self.limit().await?;
                    let res = if *overload {
                        self.lower().await?
                    } else {
                        self.raise().await?
                    };
                    if current != res {
                        info!("overload status is {}, EPS rate limit changed from {} to {}", overload, current, res);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn new(min_eps: u64, max_eps: u64) -> Result<Self> {
        if min_eps > max_eps {
            return Err(anyhow!("min_eps cannot be greater than max_eps"));
        }
        if max_eps == 0 || min_eps == 0 {
            Ok(Self { max_eps, min_eps, limiter: None, overload: Arc::new(RwLock::new(false)) })
        } else {
            let initial = min_eps + (max_eps - min_eps) / 2;
            let limiter = Ratelimiter::builder(initial, Duration::from_secs(1))
                .max_tokens(initial)
                .initial_available(initial)
                .build()?;
            Ok(Self {
                max_eps,
                min_eps,
                limiter: Some(Arc::new(RwLock::new(limiter))),
                overload: Arc::new(RwLock::new(false)),
            })
        }
    }

    async fn limit(&self) -> Result<u64> {
        let limiter = self.limiter.as_ref().ok_or(anyhow!("limiter is not initialized"))?;
        Ok(limiter.read().await.max_tokens())
    }

    async fn modify_limit(&self, raise: bool) -> Result<u64> {
        let limiter = self.limiter.as_ref().ok_or(anyhow!("limiter is not initialized"))?;
        let current = limiter.write().await.max_tokens();
        let mut target: u64;
        if raise {
            // raise by 100th of the difference between min and max
            target = current + (self.max_eps - self.min_eps) / 100;
            if target > self.max_eps {
                target = self.max_eps;
            }
        } else {
            // lower by 10th of the difference between min and max
            target = current - (self.max_eps - self.min_eps) / 10;
            if target < self.min_eps {
                target = self.min_eps;
            }
        }

        let target_refill = std::cmp::min(target, current);
        let lim = limiter.write().await;
        lim.set_refill_amount(target_refill)?;
        lim.set_max_tokens(target)?;
        // set available to the new target if it's less than the current available
        let target_avail = std::cmp::min(target, lim.available());
        lim.set_available(target_avail)?;
        // workaround for refill and max_tokens cannot be set at the same time
        if target_refill != target {
            lim.set_refill_amount(target)?;
        }
        Ok(target)
    }

    pub async fn raise(&self) -> Result<u64> {
        self.modify_limit(true).await
    }

    pub async fn lower(&self) -> Result<u64> {
        self.modify_limit(false).await
    }
}

#[cfg(test)]
#[tracing_test::traced_test]
#[tokio::test]
async fn test_eps_limiter() {
    // test the new function

    let eps = EpsLimiter::new(0, 0).unwrap();
    assert!(eps.limiter.is_none());
    assert!(eps.limit().await.is_err());
    let eps = EpsLimiter::new(3, 1);
    assert!(eps.is_err());

    // test the raise function
    let eps = EpsLimiter::new(1, 101).unwrap();
    assert_eq!(eps.limit().await.unwrap(), 51); // initial value
    let result = eps.raise().await.unwrap();
    let current = eps.limit().await.unwrap();
    assert_eq!(result, current);
    assert_eq!(current, 52);
    for _ in 1..55 {
        eps.raise().await.unwrap(); // enough to reach the max
    }
    assert_eq!(eps.limit().await.unwrap(), 101);

    // test the lower function
    let eps = EpsLimiter::new(1, 11).unwrap();
    assert_eq!(eps.limit().await.unwrap(), 6); // initial value
    let result = eps.lower().await.unwrap();
    let current = eps.limit().await.unwrap();
    assert_eq!(result, current);
    assert_eq!(current, 5);
    for _ in 1..8 {
        eps.lower().await.unwrap(); // enough to reach the min
    }
    assert_eq!(eps.limit().await.unwrap(), 1);

    // test the start function

    debug!("testing the start now");
    let (bp_tx, bp_rx) = tokio::sync::mpsc::channel(3);
    let (cancel_tx, _) = tokio::sync::broadcast::channel(3);
    let eps = EpsLimiter::new(1, 101).unwrap();

    let tx = cancel_tx.clone();
    tokio::task::spawn(async move {
        _ = eps.start(tx, bp_rx).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_secs(EPS_ADJUSTMENT_INTERVAL_IN_SECONDS + 3)).await;
    assert!(logs_contain("overload status is false"));
    bp_tx.send(true).await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_secs(EPS_ADJUSTMENT_INTERVAL_IN_SECONDS + 3)).await;
    assert!(logs_contain("overload status is true"));
    cancel_tx.send(()).unwrap();
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    assert!(logs_contain("cancel signal received"));
}
