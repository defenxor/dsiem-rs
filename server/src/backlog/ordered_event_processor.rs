//! Order-preserving event processor that maintains temporal sequence for SIEM rule processing
//! This module addresses the critical requirement that events must be processed in chronological order
//! for proper multi-stage incident detection and rule correlation.

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::{debug, error, warn};

use crate::event::NormalizedEvent;

/// Event processor that maintains strict temporal ordering while still providing performance benefits
pub struct OrderedEventProcessor {
    config: OrderingConfig,
    // Per-backlog ordered queues to maintain sequence within each incident
    backlog_queues: Arc<RwLock<BTreeMap<String, OrderedEventQueue>>>,
    // Global ordering buffer for new events
    ordering_buffer: Arc<RwLock<OrderingBuffer>>,
    processing_semaphore: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct OrderingConfig {
    /// Maximum time to wait for out-of-order events before processing
    pub max_ordering_delay_ms: u64,
    /// Maximum number of events to buffer per backlog
    pub max_buffer_size_per_backlog: usize,
    /// How often to check for processable events
    pub processing_interval_ms: u64,
    /// Maximum number of concurrent processing tasks
    pub max_concurrent_processing: usize,
    /// Whether to enforce strict ordering (vs best-effort)
    pub strict_ordering: bool,
}

impl Default for OrderingConfig {
    fn default() -> Self {
        Self {
            max_ordering_delay_ms: 1000, // 1 second tolerance for out-of-order events
            max_buffer_size_per_backlog: 1000,
            processing_interval_ms: 10, // Check every 10ms for processable events
            max_concurrent_processing: 4,
            strict_ordering: true,
        }
    }
}

/// Ordered queue for a specific backlog that maintains temporal sequence
struct OrderedEventQueue {
    backlog_id: String,
    // Events ordered by timestamp
    events: BTreeMap<DateTime<Utc>, Vec<NormalizedEvent>>,
    // Last processed timestamp to ensure ordering
    last_processed_timestamp: Option<DateTime<Utc>>,
    // Buffer for events that arrive out of order
    out_of_order_buffer: VecDeque<(NormalizedEvent, Instant)>,
    // Statistics
    total_events_received: usize,
    out_of_order_events: usize,
    events_processed: usize,
}

impl OrderedEventQueue {
    fn new(backlog_id: String) -> Self {
        Self {
            backlog_id,
            events: BTreeMap::new(),
            last_processed_timestamp: None,
            out_of_order_buffer: VecDeque::new(),
            total_events_received: 0,
            out_of_order_events: 0,
            events_processed: 0,
        }
    }

    /// Add an event to the queue, handling out-of-order events appropriately
    fn add_event(&mut self, event: NormalizedEvent, config: &OrderingConfig) -> Result<()> {
        self.total_events_received += 1;

        // Check if this event is out of order
        if let Some(last_ts) = self.last_processed_timestamp {
            if event.timestamp < last_ts {
                self.out_of_order_events += 1;

                if config.strict_ordering {
                    warn!(
                        backlog.id = self.backlog_id,
                        event.id = event.id,
                        event_timestamp = %event.timestamp,
                        last_processed = %last_ts,
                        "Strict ordering enabled: discarding out-of-order event"
                    );
                    return Ok(());
                } else {
                    // Buffer the out-of-order event with arrival time
                    self.out_of_order_buffer.push_back((event, Instant::now()));
                    return Ok(());
                }
            }
        }

        // Add to the ordered events map
        self.events.entry(event.timestamp).or_insert_with(Vec::new).push(event);
        Ok(())
    }

    /// Get the next batch of events that can be processed while maintaining order
    fn get_processable_events(&mut self, config: &OrderingConfig) -> Vec<NormalizedEvent> {
        let mut processable_events = Vec::new();
        let now = Instant::now();

        // First, check if any buffered out-of-order events can now be processed
        self.process_buffered_events(config, now);

        // Find the earliest timestamp that we can safely process
        let cutoff_time = if config.strict_ordering {
            // In strict mode, only process events up to the last processed timestamp
            self.last_processed_timestamp
        } else {
            // In non-strict mode, allow some delay for out-of-order events
            Some(Utc::now() - chrono::Duration::milliseconds(config.max_ordering_delay_ms as i64))
        };

        // Extract events that can be processed
        let mut timestamps_to_remove = Vec::new();

        for (&timestamp, events) in self.events.iter() {
            if let Some(cutoff) = cutoff_time {
                if timestamp > cutoff {
                    break; // Stop at the first event that's too recent
                }
            }

            // All events at this timestamp can be processed
            processable_events.extend(events.clone());
            timestamps_to_remove.push(timestamp);
            self.last_processed_timestamp = Some(timestamp);
        }

        // Remove processed events from the map
        for ts in timestamps_to_remove {
            self.events.remove(&ts);
        }

        self.events_processed += processable_events.len();

        if !processable_events.is_empty() {
            debug!(
                backlog.id = self.backlog_id,
                "Processing {} events in order, last timestamp: {:?}",
                processable_events.len(),
                self.last_processed_timestamp
            );
        }

        processable_events
    }

    /// Process events that were buffered due to being out of order
    fn process_buffered_events(&mut self, config: &OrderingConfig, now: Instant) {
        let max_wait = Duration::from_millis(config.max_ordering_delay_ms);

        // Check buffered events to see if they can now be processed
        let mut events_to_reprocess = Vec::new();

        while let Some((_event, arrival_time)) = self.out_of_order_buffer.front() {
            if now.duration_since(*arrival_time) >= max_wait {
                // This event has waited long enough, process it
                events_to_reprocess.push(self.out_of_order_buffer.pop_front().unwrap().0);
            } else {
                break; // Subsequent events will have arrived later
            }
        }

        // Add the waited events to the main queue
        for event in events_to_reprocess {
            self.events.entry(event.timestamp).or_insert_with(Vec::new).push(event);
        }
    }

    fn get_stats(&self) -> QueueStats {
        QueueStats {
            backlog_id: self.backlog_id.clone(),
            total_events_received: self.total_events_received,
            out_of_order_events: self.out_of_order_events,
            events_processed: self.events_processed,
            current_queue_size: self.events.values().map(|v| v.len()).sum(),
            buffered_out_of_order: self.out_of_order_buffer.len(),
        }
    }
}

/// Global ordering buffer for new events before they're assigned to backlogs
struct OrderingBuffer {
    events: BTreeMap<DateTime<Utc>, Vec<NormalizedEvent>>,
    last_processed: Option<DateTime<Utc>>,
}

impl OrderingBuffer {
    fn new() -> Self {
        Self { events: BTreeMap::new(), last_processed: None }
    }

    fn add_event(&mut self, event: NormalizedEvent) {
        self.events.entry(event.timestamp).or_insert_with(Vec::new).push(event);
    }

    fn get_processable_events(&mut self, max_delay: Duration) -> Vec<NormalizedEvent> {
        let cutoff_time = Utc::now() - chrono::Duration::from_std(max_delay).unwrap_or_default();
        let mut processable = Vec::new();
        let mut to_remove = Vec::new();

        for (&timestamp, events) in self.events.iter() {
            if timestamp <= cutoff_time {
                processable.extend(events.clone());
                to_remove.push(timestamp);
                self.last_processed = Some(timestamp);
            } else {
                break;
            }
        }

        for ts in to_remove {
            self.events.remove(&ts);
        }

        processable
    }
}

#[derive(Debug, Clone)]
pub struct QueueStats {
    pub backlog_id: String,
    pub total_events_received: usize,
    pub out_of_order_events: usize,
    pub events_processed: usize,
    pub current_queue_size: usize,
    pub buffered_out_of_order: usize,
}

impl OrderedEventProcessor {
    pub fn new(config: OrderingConfig) -> Self {
        Self {
            processing_semaphore: Arc::new(Semaphore::new(config.max_concurrent_processing)),
            config,
            backlog_queues: Arc::new(RwLock::new(BTreeMap::new())),
            ordering_buffer: Arc::new(RwLock::new(OrderingBuffer::new())),
        }
    }

    /// Process events while maintaining strict temporal ordering
    pub async fn process_events<F, Fut>(
        &self,
        mut event_rx: mpsc::Receiver<NormalizedEvent>,
        processor: F,
    ) -> Result<()>
    where
        F: Fn(Vec<NormalizedEvent>) -> Fut + Send + Sync + 'static + Clone,
        Fut: std::future::Future<Output = Result<()>> + Send,
    {
        // Start the periodic processing task
        let processor_clone = processor.clone();
        let queues_clone = self.backlog_queues.clone();
        let config_clone = self.config.clone();
        let semaphore_clone = self.processing_semaphore.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(config_clone.processing_interval_ms));

            loop {
                interval.tick().await;

                let _permit = semaphore_clone.acquire().await.unwrap();
                let processor = processor_clone.clone();
                let queues = queues_clone.clone();
                let config = config_clone.clone();

                tokio::spawn(async move {
                    if let Err(e) = Self::process_queued_events(queues, config, processor).await {
                        error!("Error processing queued events: {}", e);
                    }
                });
            }
        });

        // Main event reception loop
        while let Some(event) = event_rx.recv().await {
            self.add_event_to_queue(event).await?;
        }

        Ok(())
    }

    async fn add_event_to_queue(&self, event: NormalizedEvent) -> Result<()> {
        // For new events without a backlog assignment, use the global buffer
        // In a real implementation, this would determine the backlog based on the event
        let backlog_id = self.determine_backlog_id(&event).await;

        let mut queues = self.backlog_queues.write().await;

        // Create queue for new backlog if needed
        if !queues.contains_key(&backlog_id) {
            queues.insert(backlog_id.clone(), OrderedEventQueue::new(backlog_id.clone()));
        }

        if let Some(queue) = queues.get_mut(&backlog_id) {
            queue.add_event(event, &self.config)?;
        }

        Ok(())
    }

    async fn determine_backlog_id(&self, event: &NormalizedEvent) -> String {
        // Simplified backlog determination - in reality this would be more complex
        // and might involve checking existing backlogs for matches
        format!("backlog_{}_{}_{}", event.plugin_id, event.src_ip, event.dst_ip)
    }

    async fn process_queued_events<F, Fut>(
        queues: Arc<RwLock<BTreeMap<String, OrderedEventQueue>>>,
        config: OrderingConfig,
        processor: F,
    ) -> Result<()>
    where
        F: Fn(Vec<NormalizedEvent>) -> Fut + Send,
        Fut: std::future::Future<Output = Result<()>> + Send,
    {
        let mut all_processable_events = Vec::new();

        {
            let mut queues_guard = queues.write().await;

            // Process each backlog queue
            for (_, queue) in queues_guard.iter_mut() {
                let processable = queue.get_processable_events(&config);
                all_processable_events.extend(processable);
            }

            // Remove empty queues to prevent memory leaks
            queues_guard.retain(|_, queue| queue.events.len() + queue.out_of_order_buffer.len() > 0);
        }

        // Process the events if we have any
        if !all_processable_events.is_empty() {
            // Sort by timestamp to maintain global ordering
            all_processable_events.sort_by_key(|event| event.timestamp);

            debug!("Processing {} ordered events", all_processable_events.len());
            processor(all_processable_events).await?;
        }

        Ok(())
    }

    /// Get statistics for all queues
    pub async fn get_all_queue_stats(&self) -> Vec<QueueStats> {
        let queues = self.backlog_queues.read().await;
        queues.values().map(|queue| queue.get_stats()).collect()
    }

    /// Get configuration
    pub fn get_config(&self) -> &OrderingConfig {
        &self.config
    }

    /// Update configuration at runtime
    pub async fn update_config(&mut self, new_config: OrderingConfig) {
        self.config = new_config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn test_ordered_queue_in_order_events() {
        let mut queue = OrderedEventQueue::new("test-backlog".to_string());
        let config = OrderingConfig::default();

        let base_time = Utc::now();

        // Add events in order
        for i in 0..5 {
            let event = NormalizedEvent {
                id: format!("event-{}", i),
                timestamp: base_time + ChronoDuration::seconds(i),
                ..Default::default()
            };
            queue.add_event(event, &config).unwrap();
        }

        let processable = queue.get_processable_events(&config);
        assert_eq!(processable.len(), 5);

        // Events should be in order
        for (i, event) in processable.iter().enumerate() {
            assert_eq!(event.id, format!("event-{}", i));
        }
    }

    #[test]
    fn test_ordered_queue_out_of_order_strict() {
        let mut queue = OrderedEventQueue::new("test-backlog".to_string());
        let mut config = OrderingConfig::default();
        config.strict_ordering = true;

        let base_time = Utc::now();

        // Add first event
        let event1 = NormalizedEvent {
            id: "event-1".to_string(),
            timestamp: base_time + ChronoDuration::seconds(1),
            ..Default::default()
        };
        queue.add_event(event1, &config).unwrap();

        // Process it
        let processable = queue.get_processable_events(&config);
        assert_eq!(processable.len(), 1);

        // Add out-of-order event (should be discarded in strict mode)
        let event_out_of_order = NormalizedEvent {
            id: "event-out-of-order".to_string(),
            timestamp: base_time, // Earlier than event-1
            ..Default::default()
        };
        queue.add_event(event_out_of_order, &config).unwrap();

        // Should have no new processable events
        let processable = queue.get_processable_events(&config);
        assert_eq!(processable.len(), 0);

        let stats = queue.get_stats();
        assert_eq!(stats.out_of_order_events, 1);
    }

    #[tokio::test]
    async fn test_ordered_processor() {
        let config = OrderingConfig { max_ordering_delay_ms: 100, strict_ordering: false, ..Default::default() };

        let processor = OrderedEventProcessor::new(config);
        let (tx, rx) = mpsc::channel(100);

        // Start processing
        let processor_clone = processor.clone();
        tokio::spawn(async move {
            processor_clone
                .process_events(rx, |events| async move {
                    // Simple processor that just logs
                    debug!("Processed {} events", events.len());
                    Ok(())
                })
                .await
                .unwrap();
        });

        // Send some events
        for i in 0..10 {
            let event = NormalizedEvent {
                id: format!("event-{}", i),
                timestamp: Utc::now() + ChronoDuration::seconds(i),
                ..Default::default()
            };
            tx.send(event).await.unwrap();
        }

        // Give some time for processing
        tokio::time::sleep(Duration::from_millis(200)).await;

        let stats = processor.get_all_queue_stats().await;
        assert!(!stats.is_empty());
    }
}

impl Clone for OrderedEventProcessor {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            backlog_queues: self.backlog_queues.clone(),
            ordering_buffer: self.ordering_buffer.clone(),
            processing_semaphore: self.processing_semaphore.clone(),
        }
    }
}
