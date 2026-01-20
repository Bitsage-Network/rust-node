//! Circuit Breaker Pattern for External Service Calls
//!
//! Implements the circuit breaker pattern to prevent cascading failures when calling
//! external services like blockchain RPC endpoints.
//!
//! States:
//! - Closed: Normal operation, requests pass through
//! - Open: Failures exceeded threshold, requests rejected immediately
//! - HalfOpen: Testing if service recovered, limited requests allowed

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn, error};

/// Circuit breaker state
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    /// Circuit is closed, requests pass through normally
    Closed,
    /// Circuit is open, requests are rejected immediately
    Open,
    /// Circuit is half-open, testing if service recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: usize,
    /// Time window for counting failures (seconds)
    pub failure_window: Duration,
    /// Time to wait before attempting to close circuit (seconds)
    pub reset_timeout: Duration,
    /// Number of successful requests needed to close circuit from half-open
    pub success_threshold: usize,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            failure_window: Duration::from_secs(60),
            reset_timeout: Duration::from_secs(30),
            success_threshold: 2,
        }
    }
}

/// Circuit breaker statistics
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub total_requests: u64,
    pub total_failures: u64,
    pub total_successes: u64,
    pub total_rejections: u64,
    pub current_state: CircuitState,
    pub last_state_change: Instant,
}

/// Circuit breaker internal state
struct CircuitBreakerState {
    state: CircuitState,
    failure_count: usize,
    success_count: usize,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
    stats: CircuitStats,
}

/// Circuit breaker for protecting against cascading failures
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitBreakerState>>,
}

impl CircuitBreaker {
    /// Create new circuit breaker with config
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState {
                state: CircuitState::Closed,
                failure_count: 0,
                success_count: 0,
                last_failure_time: None,
                last_state_change: Instant::now(),
                stats: CircuitStats {
                    total_requests: 0,
                    total_failures: 0,
                    total_successes: 0,
                    total_rejections: 0,
                    current_state: CircuitState::Closed,
                    last_state_change: Instant::now(),
                },
            })),
        }
    }

    /// Execute a function with circuit breaker protection
    pub async fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        // Check if circuit allows request
        {
            let mut state = self.state.write().await;
            state.stats.total_requests += 1;

            match state.state {
                CircuitState::Open => {
                    // Check if enough time has passed to try half-open
                    if state.last_state_change.elapsed() >= self.config.reset_timeout {
                        debug!("Circuit breaker transitioning to HalfOpen");
                        state.state = CircuitState::HalfOpen;
                        state.success_count = 0;
                        state.last_state_change = Instant::now();
                        state.stats.current_state = CircuitState::HalfOpen;
                    } else {
                        state.stats.total_rejections += 1;
                        warn!("Circuit breaker OPEN - request rejected");
                        return Err(CircuitBreakerError::CircuitOpen);
                    }
                }
                CircuitState::HalfOpen => {
                    debug!("Circuit breaker in HalfOpen state, allowing test request");
                }
                CircuitState::Closed => {
                    // Reset failure count if outside failure window
                    if let Some(last_failure) = state.last_failure_time {
                        if last_failure.elapsed() >= self.config.failure_window {
                            state.failure_count = 0;
                            state.last_failure_time = None;
                        }
                    }
                }
            }
        }

        // Execute the function
        let result = f.await;

        // Update circuit state based on result
        let mut state = self.state.write().await;
        match result {
            Ok(value) => {
                state.stats.total_successes += 1;

                match state.state {
                    CircuitState::HalfOpen => {
                        state.success_count += 1;
                        if state.success_count >= self.config.success_threshold {
                            debug!("Circuit breaker closing after {} successes", state.success_count);
                            state.state = CircuitState::Closed;
                            state.failure_count = 0;
                            state.last_failure_time = None;
                            state.last_state_change = Instant::now();
                            state.stats.current_state = CircuitState::Closed;
                        }
                    }
                    CircuitState::Closed => {
                        // Reset failure count on success
                        if state.failure_count > 0 {
                            state.failure_count = 0;
                            state.last_failure_time = None;
                        }
                    }
                    _ => {}
                }

                Ok(value)
            }
            Err(e) => {
                state.stats.total_failures += 1;
                state.failure_count += 1;
                state.last_failure_time = Some(Instant::now());

                match state.state {
                    CircuitState::HalfOpen => {
                        error!("Circuit breaker opening - failure in HalfOpen state");
                        state.state = CircuitState::Open;
                        state.last_state_change = Instant::now();
                        state.stats.current_state = CircuitState::Open;
                    }
                    CircuitState::Closed => {
                        if state.failure_count >= self.config.failure_threshold {
                            error!(
                                "Circuit breaker opening - {} failures in {} seconds",
                                state.failure_count,
                                self.config.failure_window.as_secs()
                            );
                            state.state = CircuitState::Open;
                            state.last_state_change = Instant::now();
                            state.stats.current_state = CircuitState::Open;
                        }
                    }
                    _ => {}
                }

                Err(CircuitBreakerError::RequestFailed(e))
            }
        }
    }

    /// Get current circuit stats
    pub async fn stats(&self) -> CircuitStats {
        self.state.read().await.stats.clone()
    }

    /// Force reset circuit to closed state
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        state.state = CircuitState::Closed;
        state.failure_count = 0;
        state.success_count = 0;
        state.last_failure_time = None;
        state.last_state_change = Instant::now();
        state.stats.current_state = CircuitState::Closed;
        debug!("Circuit breaker manually reset");
    }
}

/// Circuit breaker error
#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    /// Circuit is open, request rejected
    CircuitOpen,
    /// Request failed
    RequestFailed(E),
}

impl<E: std::fmt::Display> std::fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitBreakerError::CircuitOpen => {
                write!(f, "Circuit breaker is open - too many recent failures")
            }
            CircuitBreakerError::RequestFailed(e) => write!(f, "Request failed: {}", e),
        }
    }
}

impl<E: std::error::Error> std::error::Error for CircuitBreakerError<E> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_closes_after_successes() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            reset_timeout: Duration::from_secs(1),
            success_threshold: 2,
        };

        let cb = CircuitBreaker::new(config);

        // Cause failures to open circuit
        for _ in 0..3 {
            let result = cb.call(async { Err::<(), _>("fail") }).await;
            assert!(result.is_err());
        }

        // Circuit should be open
        let stats = cb.stats().await;
        assert_eq!(stats.current_state, CircuitState::Open);

        // Wait for reset timeout
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Next request should transition to HalfOpen
        let _ = cb.call(async { Ok::<(), String>(()) }).await;

        // One more success should close circuit
        let _ = cb.call(async { Ok::<(), String>(()) }).await;

        let stats = cb.stats().await;
        assert_eq!(stats.current_state, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            failure_window: Duration::from_secs(60),
            reset_timeout: Duration::from_secs(5),
            success_threshold: 1,
        };

        let cb = CircuitBreaker::new(config);

        // First failure
        let result = cb.call(async { Err::<(), _>("fail1") }).await;
        assert!(matches!(result, Err(CircuitBreakerError::RequestFailed(_))));

        // Second failure should open circuit
        let result = cb.call(async { Err::<(), _>("fail2") }).await;
        assert!(matches!(result, Err(CircuitBreakerError::RequestFailed(_))));

        // Circuit should be open now
        let stats = cb.stats().await;
        assert_eq!(stats.current_state, CircuitState::Open);

        // Next request should be rejected
        let result = cb.call(async { Ok::<(), String>(()) }).await;
        assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen)));
    }
}
