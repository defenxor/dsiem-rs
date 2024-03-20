use anyhow::{anyhow, Result};
use std::thread::available_parallelism;

// this is based on benchmarking result on an i7-12700F desktop

// with cache
const MAX_CHECKS_PER_THREAD: usize = 100_000_000;

// without cache
// const MAX_CHECKS_PER_THREAD: usize = 17_350_000;

const TOKIO_MIN_THREADS: usize = 1;
const MIN_AVAILABLE_PARALLELISM: usize = 2;

#[derive(Clone)]
pub struct ThreadAllocation {
    pub filter_threads: usize,
    pub tokio_threads: usize,
}

pub fn calculate(
    num_of_directives: usize,
    max_eps: usize,
    requested_filter_threads: Option<usize>,
    test_parallelism: Option<usize>,
) -> Result<ThreadAllocation> {
    let mut max_threads = available_parallelism()?.get();
    if let Some(v) = test_parallelism {
        max_threads = v;
    }

    if MIN_AVAILABLE_PARALLELISM > max_threads {
        return Err(anyhow!(
            "available parallelism is too low: {}, at least {} are required",
            max_threads,
            MIN_AVAILABLE_PARALLELISM
        ));
    }

    if let Some(n) = requested_filter_threads {
        // at least 1 should be for tokio
        if n > max_threads - TOKIO_MIN_THREADS {
            return Err(anyhow!(
                "available parallelism is ({}), at most {} threads can be used for filtering",
                max_threads,
                max_threads - TOKIO_MIN_THREADS
            ));
        } else {
            return Ok(ThreadAllocation {
                filter_threads: n,
                tokio_threads: max_threads - n,
            });
        }
    }

    // auto allocation

    let dirs_per_thread = MAX_CHECKS_PER_THREAD / max_eps;

    let div_up = |a: usize, b: usize| -> usize { (a as f32 / b as f32).ceil() as usize };

    // minimum 1 for filter thread
    let filter_threads = match div_up(num_of_directives, dirs_per_thread) {
        0 => 1,
        _ => div_up(num_of_directives, dirs_per_thread),
    };
    if filter_threads > (max_threads - TOKIO_MIN_THREADS) {
        return Err(anyhow!(
          "too many directives ({}) and/or anticipated EPS ({}) for the available parallelism ({}), reduce the number of directives or max_eps and try again",
          num_of_directives,
          max_eps,
          max_threads
        ));
    }
    Ok(ThreadAllocation {
        filter_threads,
        tokio_threads: max_threads - filter_threads,
    })
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_calculate() {
        // 1 cpu available
        let a = calculate(1000, 1000, None, Some(1));
        assert!(a.is_err());

        // 2 cpus available
        let a = calculate(1000, 1000, None, Some(2)).unwrap();
        assert_eq!(a.filter_threads, 1);
        assert_eq!(a.tokio_threads, 1);

        // trait used in manager_opt
        let b = a.clone();
        assert!(b.filter_threads == a.filter_threads);

        // 4 cpus available
        let a = calculate(1000, 1000, None, Some(4)).unwrap();
        assert_eq!(a.filter_threads, 1);
        assert_eq!(a.tokio_threads, 3);

        // 4 cpus available, EPS low enough for 1 thread
        let a = calculate(1000, 17300, None, Some(4)).unwrap();
        assert_eq!(a.filter_threads, 1);

        // 4 cpus available, EPS cross the threshold for 1 thread
        let a = calculate(10001, 10000, None, Some(4)).unwrap();
        assert_eq!(a.filter_threads, 2);

        // 4 cpus available, user request 3 filter threads
        let a = calculate(10000, 1000, Some(3), Some(4)).unwrap();
        assert_eq!(a.filter_threads, 3);
        assert_eq!(a.tokio_threads, 1);

        // 2 cpus available, too many directives and/or too high max_eps
        let a = calculate(10000, 11000, None, Some(2));
        assert!(a.is_err());

        // 2 cpus available, user request too many filter threads
        let a = calculate(1000, 1000, Some(2), Some(2));
        assert!(a.is_err());
    }
}
