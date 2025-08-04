use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

// Custom serde module for Instant serialization
mod instant_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = instant.elapsed();
        let timestamp = SystemTime::now() - duration;
        let epoch_duration = timestamp.duration_since(UNIX_EPOCH).map_err(serde::ser::Error::custom)?;
        epoch_duration.as_nanos().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let nanos = u128::deserialize(deserializer)?;
        let duration = Duration::from_nanos(nanos as u64);
        let system_time = UNIX_EPOCH + duration;
        let now = SystemTime::now();
        let instant_offset = now.duration_since(system_time).map_err(serde::de::Error::custom)?;
        Ok(Instant::now() - instant_offset)
    }
}

/// Performance monitor that tracks backlog processing metrics and provides adaptive optimizations
pub struct BacklogPerformanceMonitor {
    metrics: Arc<RwLock<PerformanceMetrics>>,
    config: MonitorConfig,
    optimization_history: Arc<RwLock<VecDeque<OptimizationEvent>>>,
    last_optimization: Arc<RwLock<Instant>>,
}

#[derive(Clone)]
pub struct MonitorConfig {
    pub sample_window: Duration,
    pub optimization_interval: Duration,
    pub latency_threshold_ms: u64,
    pub throughput_threshold_eps: u64,
    pub memory_threshold_mb: u64,
    pub cpu_threshold_percent: f64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            sample_window: Duration::from_secs(60),
            optimization_interval: Duration::from_secs(300), // 5 minutes
            latency_threshold_ms: 100,
            throughput_threshold_eps: 1000, // events per second
            memory_threshold_mb: 1024,
            cpu_threshold_percent: 80.0,
        }
    }
}

#[derive(Debug, Default)]
pub struct PerformanceMetrics {
    // Throughput metrics
    pub events_processed: AtomicU64,
    pub events_per_second: AtomicU64,
    pub peak_events_per_second: AtomicU64,

    // Latency metrics
    pub avg_processing_latency_ns: AtomicU64,
    pub p95_latency_ns: AtomicU64,
    pub p99_latency_ns: AtomicU64,

    // Resource usage
    pub memory_usage_mb: AtomicU64,
    pub cpu_usage_percent: AtomicU64,
    pub active_backlogs: AtomicUsize,
    pub queue_depth: AtomicUsize,

    // Error rates
    pub timeout_rate: AtomicU64,
    pub error_rate: AtomicU64,

    // Cache performance
    pub cache_hit_rate: AtomicU64,
    pub cache_miss_rate: AtomicU64,

    // Timestamps
    pub last_updated: AtomicU64,
    pub measurement_start: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationEvent {
    #[serde(with = "instant_serde")]
    pub timestamp: Instant,
    pub optimization_type: OptimizationType,
    pub before_metrics: PerformanceSnapshot,
    pub after_metrics: Option<PerformanceSnapshot>,
    pub success: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationType {
    CacheResize,
    ThreadPoolAdjustment,
    BatchSizeOptimization,
    QueueDepthAdjustment,
    MemoryOptimization,
    LoadBalancing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    #[serde(with = "instant_serde")]
    pub timestamp: Instant,
    pub events_per_second: u64,
    pub avg_latency_ms: f64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f64,
    pub active_backlogs: usize,
    pub cache_hit_rate: f64,
}

pub struct LatencyTracker {
    samples: VecDeque<u64>,
    max_samples: usize,
}

impl LatencyTracker {
    fn new(max_samples: usize) -> Self {
        Self { samples: VecDeque::with_capacity(max_samples), max_samples }
    }

    fn add_sample(&mut self, latency_ns: u64) {
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(latency_ns);
    }

    fn calculate_percentile(&self, percentile: f64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }

        let mut sorted: Vec<u64> = self.samples.iter().copied().collect();
        sorted.sort_unstable();

        let index = ((sorted.len() as f64 - 1.0) * percentile / 100.0) as usize;
        sorted[index.min(sorted.len() - 1)]
    }

    fn average(&self) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        self.samples.iter().sum::<u64>() / self.samples.len() as u64
    }
}

impl BacklogPerformanceMonitor {
    pub fn new(config: MonitorConfig) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            config,
            optimization_history: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
            last_optimization: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Record processing latency for an event
    pub async fn record_latency(&self, latency_ns: u64) {
        let metrics = self.metrics.read().await;

        // Update average latency using exponential moving average
        let current_avg = metrics.avg_processing_latency_ns.load(Ordering::Relaxed);
        let alpha = 0.1; // Smoothing factor
        let new_avg = if current_avg == 0 {
            latency_ns
        } else {
            ((1.0 - alpha) * current_avg as f64 + alpha * latency_ns as f64) as u64
        };

        metrics.avg_processing_latency_ns.store(new_avg, Ordering::Relaxed);
        metrics.last_updated.store(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64,
            Ordering::Relaxed,
        );
    }

    /// Record throughput metrics
    pub async fn record_throughput(&self, events_count: u64, time_window: Duration) {
        let eps = (events_count as f64 / time_window.as_secs_f64()) as u64;
        let metrics = self.metrics.read().await;

        metrics.events_per_second.store(eps, Ordering::Relaxed);
        metrics.events_processed.fetch_add(events_count, Ordering::Relaxed);

        // Update peak EPS
        let current_peak = metrics.peak_events_per_second.load(Ordering::Relaxed);
        if eps > current_peak {
            metrics.peak_events_per_second.store(eps, Ordering::Relaxed);
        }
    }

    /// Update resource usage metrics
    pub async fn update_resource_usage(
        &self,
        memory_mb: u64,
        cpu_percent: f64,
        active_backlogs: usize,
        queue_depth: usize,
    ) {
        let metrics = self.metrics.read().await;

        metrics.memory_usage_mb.store(memory_mb, Ordering::Relaxed);
        metrics.cpu_usage_percent.store((cpu_percent * 100.0) as u64, Ordering::Relaxed);
        metrics.active_backlogs.store(active_backlogs, Ordering::Relaxed);
        metrics.queue_depth.store(queue_depth, Ordering::Relaxed);
    }

    /// Update cache performance metrics
    pub async fn update_cache_metrics(&self, hit_rate: f64, miss_rate: f64) {
        let metrics = self.metrics.read().await;

        metrics.cache_hit_rate.store((hit_rate * 100.0) as u64, Ordering::Relaxed);
        metrics.cache_miss_rate.store((miss_rate * 100.0) as u64, Ordering::Relaxed);
    }

    /// Get current performance snapshot
    pub async fn get_performance_snapshot(&self) -> PerformanceSnapshot {
        let metrics = self.metrics.read().await;

        PerformanceSnapshot {
            timestamp: Instant::now(),
            events_per_second: metrics.events_per_second.load(Ordering::Relaxed),
            avg_latency_ms: metrics.avg_processing_latency_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            memory_usage_mb: metrics.memory_usage_mb.load(Ordering::Relaxed),
            cpu_usage_percent: metrics.cpu_usage_percent.load(Ordering::Relaxed) as f64 / 100.0,
            active_backlogs: metrics.active_backlogs.load(Ordering::Relaxed),
            cache_hit_rate: metrics.cache_hit_rate.load(Ordering::Relaxed) as f64 / 100.0,
        }
    }

    /// Analyze performance and suggest optimizations
    pub async fn analyze_and_optimize(&self) -> Vec<OptimizationRecommendation> {
        let last_opt = *self.last_optimization.read().await;
        if last_opt.elapsed() < self.config.optimization_interval {
            return vec![];
        }

        let snapshot = self.get_performance_snapshot().await;
        let mut recommendations = Vec::new();

        // Analyze latency
        if snapshot.avg_latency_ms > self.config.latency_threshold_ms as f64 {
            recommendations.push(OptimizationRecommendation {
                optimization_type: OptimizationType::BatchSizeOptimization,
                priority: Priority::High,
                description: format!(
                    "High latency detected: {:.2}ms > {}ms threshold. Consider increasing batch size or adding more processing threads.",
                    snapshot.avg_latency_ms, self.config.latency_threshold_ms
                ),
                estimated_impact: ImpactEstimate::LatencyReduction(0.3),
            });
        }

        // Analyze throughput
        if snapshot.events_per_second < self.config.throughput_threshold_eps {
            recommendations.push(OptimizationRecommendation {
                optimization_type: OptimizationType::ThreadPoolAdjustment,
                priority: Priority::Medium,
                description: format!(
                    "Low throughput detected: {} eps < {} eps threshold. Consider adding more worker threads.",
                    snapshot.events_per_second, self.config.throughput_threshold_eps
                ),
                estimated_impact: ImpactEstimate::ThroughputIncrease(0.25),
            });
        }

        // Analyze memory usage
        if snapshot.memory_usage_mb > self.config.memory_threshold_mb {
            recommendations.push(OptimizationRecommendation {
                optimization_type: OptimizationType::MemoryOptimization,
                priority: Priority::High,
                description: format!(
                    "High memory usage detected: {} MB > {} MB threshold. Consider reducing cache sizes or implementing memory compaction.",
                    snapshot.memory_usage_mb, self.config.memory_threshold_mb
                ),
                estimated_impact: ImpactEstimate::MemoryReduction(0.2),
            });
        }

        // Analyze cache performance
        if snapshot.cache_hit_rate < 0.7 {
            recommendations.push(OptimizationRecommendation {
                optimization_type: OptimizationType::CacheResize,
                priority: Priority::Medium,
                description: format!(
                    "Low cache hit rate detected: {:.1}% < 70% threshold. Consider increasing cache size or improving cache warming strategies.",
                    snapshot.cache_hit_rate * 100.0
                ),
                estimated_impact: ImpactEstimate::CacheEfficiencyIncrease(0.4),
            });
        }

        // Update last optimization time
        *self.last_optimization.write().await = Instant::now();

        recommendations
    }

    /// Apply an optimization and track its effectiveness
    pub async fn apply_optimization(&self, opt_type: OptimizationType, apply_fn: impl FnOnce() -> bool) -> bool {
        let before_snapshot = self.get_performance_snapshot().await;

        info!("Applying optimization: {:?}", opt_type);
        let success = apply_fn();

        let optimization_event = OptimizationEvent {
            timestamp: Instant::now(),
            optimization_type: opt_type.clone(),
            before_metrics: before_snapshot,
            after_metrics: None, // Will be filled later
            success,
            description: format!("Applied optimization: {:?}", opt_type),
        };

        self.optimization_history.write().await.push_back(optimization_event);

        // Schedule a task to measure the impact after some time
        let monitor = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            monitor.measure_optimization_impact().await;
        });

        success
    }

    async fn measure_optimization_impact(&self) {
        let after_snapshot = self.get_performance_snapshot().await;

        if let Some(last_event) = self.optimization_history.write().await.back_mut() {
            last_event.after_metrics = Some(after_snapshot.clone());

            // Calculate impact
            let before = &last_event.before_metrics;
            let latency_improvement = (before.avg_latency_ms - after_snapshot.avg_latency_ms) / before.avg_latency_ms;
            let throughput_improvement = (after_snapshot.events_per_second as f64 - before.events_per_second as f64)
                / before.events_per_second as f64;

            debug!(
                "Optimization impact - Latency: {:.2}% improvement, Throughput: {:.2}% improvement",
                latency_improvement * 100.0,
                throughput_improvement * 100.0
            );
        }
    }

    /// Get optimization history for analysis
    pub async fn get_optimization_history(&self) -> Vec<OptimizationEvent> {
        self.optimization_history.read().await.iter().cloned().collect()
    }

    /// Generate performance report
    pub async fn generate_report(&self) -> PerformanceReport {
        let snapshot = self.get_performance_snapshot().await;
        let history = self.get_optimization_history().await;

        PerformanceReport {
            current_snapshot: snapshot,
            optimization_history: history,
            recommendations: self.analyze_and_optimize().await,
            report_timestamp: Instant::now(),
        }
    }
}

impl Clone for BacklogPerformanceMonitor {
    fn clone(&self) -> Self {
        Self {
            metrics: self.metrics.clone(),
            config: self.config.clone(),
            optimization_history: self.optimization_history.clone(),
            last_optimization: self.last_optimization.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OptimizationRecommendation {
    pub optimization_type: OptimizationType,
    pub priority: Priority,
    pub description: String,
    pub estimated_impact: ImpactEstimate,
}

#[derive(Debug, Clone)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub enum ImpactEstimate {
    LatencyReduction(f64),        // Fraction reduction (0.0 - 1.0)
    ThroughputIncrease(f64),      // Fraction increase
    MemoryReduction(f64),         // Fraction reduction
    CacheEfficiencyIncrease(f64), // Fraction increase
}

#[derive(Debug, Clone)]
pub struct PerformanceReport {
    pub current_snapshot: PerformanceSnapshot,
    pub optimization_history: Vec<OptimizationEvent>,
    pub recommendations: Vec<OptimizationRecommendation>,
    pub report_timestamp: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_tracker() {
        let mut tracker = LatencyTracker::new(100);

        // Add some samples
        for i in 1..=100 {
            tracker.add_sample(i * 1000); // microseconds
        }

        assert_eq!(tracker.average(), 50500); // Average of 1-100 * 1000
        assert_eq!(tracker.calculate_percentile(50.0), 50000); // 50th percentile
        assert_eq!(tracker.calculate_percentile(95.0), 95000); // 95th percentile
    }

    #[tokio::test]
    async fn test_performance_monitor() {
        let config = MonitorConfig::default();
        let monitor = BacklogPerformanceMonitor::new(config);

        // Record some metrics
        monitor.record_latency(1_000_000).await; // 1ms
        monitor.record_throughput(1000, Duration::from_secs(1)).await; // 1000 EPS
        monitor.update_resource_usage(512, 50.0, 10, 100).await;
        monitor.update_cache_metrics(0.8, 0.2).await;

        let snapshot = monitor.get_performance_snapshot().await;
        assert_eq!(snapshot.events_per_second, 1000);
        assert_eq!(snapshot.memory_usage_mb, 512);
        assert_eq!(snapshot.active_backlogs, 10);
        assert!((snapshot.cache_hit_rate - 0.8).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_optimization_recommendations() {
        let mut config = MonitorConfig::default();
        config.latency_threshold_ms = 50; // Low threshold for testing
        config.optimization_interval = Duration::from_millis(1); // Very short interval for testing

        let monitor = BacklogPerformanceMonitor::new(config);

        // Record high latency to trigger metrics update
        monitor.record_latency(100_000_000).await; // 100ms

        // Wait a tiny bit to ensure interval has passed
        tokio::time::sleep(Duration::from_millis(2)).await;

        let recommendations = monitor.analyze_and_optimize().await;
        assert!(!recommendations.is_empty());
        assert!(recommendations.iter().any(|r| matches!(r.optimization_type, OptimizationType::BatchSizeOptimization)));
    }
}
