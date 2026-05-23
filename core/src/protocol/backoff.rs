use std::time::Duration;
use rand::Rng;

/// Exponential backoff with jitter for retrying failed operations.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    current_delay: Duration,
    base_delay: Duration,
    max_delay: Duration,
    factor: f64,
    jitter: f64,
}

impl ExponentialBackoff {
    /// Create a new backoff strategy.
    /// 
    /// - `base_delay`: Initial delay before the first retry.
    /// - `max_delay`: Maximum delay between retries.
    pub fn new(base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            current_delay: base_delay,
            base_delay,
            max_delay,
            factor: 2.0,
            jitter: 0.1,
        }
    }

    /// Get the next delay duration and increment the internal state.
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.current_delay;
        
        // Calculate next delay: current * factor
        let next = self.current_delay.as_secs_f64() * self.factor;
        self.current_delay = Duration::from_secs_f64(next).min(self.max_delay);
        
        // Apply jitter to the returned delay
        let mut rng = rand::thread_rng();
        let jitter_range = delay.as_secs_f64() * self.jitter;
        let jitter_value = rng.gen_range(-jitter_range..jitter_range);
        
        Duration::from_secs_f64(delay.as_secs_f64() + jitter_value).max(self.base_delay)
    }

    /// Reset the backoff to the base delay.
    pub fn reset(&mut self) {
        self.current_delay = self.base_delay;
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(30))
    }
}
