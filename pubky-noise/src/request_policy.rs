use std::future::Future;
use std::num::NonZeroU8;
use std::time::Duration;

use futures_util::future::{select, Either};
use futures_util::pin_mut;
use reqwest::StatusCode;

use crate::PubkyNoiseError;

/// Bounds network work performed by Noise's convenience APIs.
///
/// Each attempt includes request preparation and response-body consumption.
/// Its deadline includes delays in the client, network intermediaries and server.
/// Retries reuse the same resource and, for writes, the exact prepared bytes.
/// Only expired deadlines and HTTP 408/429/502/503/504 are retried; other errors,
/// including immediate connection failures, return without retrying.
/// Missing messages, authorization failures and invalid packets are not retried.
/// Callers still own authorization, overall time budgets, aggregate concurrency
/// and durable recovery.
#[derive(Clone, Copy, Debug)]
pub struct RequestPolicy {
    /// Maximum duration of one attempt, including reading the response body.
    pub timeout: Duration,
    /// Total attempts, including the first request. Set to one to disable retries.
    pub max_attempts: NonZeroU8,
    /// Delay before the first retry; subsequent delays double up to `max_backoff`.
    pub initial_backoff: Duration,
    /// Maximum delay between attempts.
    pub max_backoff: Duration,
}

impl Default for RequestPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(10_000),
            max_attempts: NonZeroU8::new(3).expect("default max attempts is 3, which is non-zero"),
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_millis(2_000),
        }
    }
}

impl RequestPolicy {
    pub(crate) async fn run<T, F, Fut>(&self, mut operation: F) -> Result<T, PubkyNoiseError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, PubkyNoiseError>>,
    {
        let mut backoff = self.initial_backoff.min(self.max_backoff);
        let mut retries_left = self.max_attempts.get() - 1;
        loop {
            let result = {
                let request = Box::pin(operation());
                let deadline = delay(self.timeout);
                pin_mut!(request, deadline);
                match select(request, deadline).await {
                    Either::Left((result, _)) => Some(result),
                    Either::Right(_) => None,
                }
            };
            match result {
                Some(Ok(value)) => return Ok(value),
                Some(Err(error)) if retries_left == 0 || !retryable(&error) => {
                    return Err(error);
                }
                None if retries_left == 0 => return Err(PubkyNoiseError::HomeserverResponseError),
                Some(Err(_)) | None => {}
            }
            retries_left -= 1;
            delay(backoff).await;
            backoff = backoff.saturating_mul(2).min(self.max_backoff);
        }
    }
}

fn retryable(error: &PubkyNoiseError) -> bool {
    let PubkyNoiseError::HomeserverHttpError { status } = error else {
        return false;
    };
    matches!(
        StatusCode::from_u16(*status),
        Ok(StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT)
    )
}

async fn delay(mut duration: Duration) {
    // Schedule each wait separately in chunks that fit browser timers'
    // signed 32-bit millisecond limit, even for a very large Duration.
    let maximum = Duration::from_millis(i32::MAX as u64);
    while duration > maximum {
        futures_timer::Delay::new(maximum).await;
        duration -= maximum;
    }
    futures_timer::Delay::new(duration).await;
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::future::pending;
    use std::time::Instant;

    fn policy(attempts: u8) -> RequestPolicy {
        RequestPolicy {
            timeout: Duration::from_millis(20),
            max_attempts: NonZeroU8::new(attempts).unwrap(),
            initial_backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(10),
        }
    }

    #[tokio::test]
    async fn retries_only_selected_transient_failures() {
        for status in [
            202, 206, 400, 401, 403, 404, 410, 408, 429, 500, 501, 502, 503, 504,
        ] {
            let calls = Cell::new(0);
            let error = PubkyNoiseError::HomeserverHttpError { status };
            let result: Result<(), _> = policy(3)
                .run(|| {
                    calls.set(calls.get() + 1);
                    std::future::ready(Err(PubkyNoiseError::HomeserverHttpError { status }))
                })
                .await;
            assert_eq!(result, Err(error));
            let expected = if matches!(status, 408 | 429 | 502 | 503 | 504) {
                3
            } else {
                1
            };
            assert_eq!(calls.get(), expected, "HTTP {status}");
        }
        let errors: [fn() -> PubkyNoiseError; 5] = [
            || PubkyNoiseError::HomeserverResponseError,
            || PubkyNoiseError::HomeserverWriteError,
            || PubkyNoiseError::BadLengthCiphertext,
            || PubkyNoiseError::DecryptionError,
            || PubkyNoiseError::RestoreBackupRollbackError,
        ];
        for error in errors {
            let calls = Cell::new(0);
            let result: Result<(), _> = policy(3)
                .run(|| {
                    calls.set(calls.get() + 1);
                    std::future::ready(Err(error()))
                })
                .await;
            assert_eq!(result, Err(error()));
            assert_eq!(calls.get(), 1);
        }
    }

    struct ActiveAttempt<'a>(&'a Cell<usize>);

    impl Drop for ActiveAttempt<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() - 1);
        }
    }

    #[tokio::test]
    async fn timeout_drops_each_attempt_before_retrying() {
        let active = Cell::new(0);
        let calls = Cell::new(0);
        let result = policy(3)
            .run(|| async {
                assert_eq!(active.get(), 0, "a previous attempt is still alive");
                active.set(1);
                let _guard = ActiveAttempt(&active);
                calls.set(calls.get() + 1);
                pending::<Result<(), PubkyNoiseError>>().await
            })
            .await;
        assert_eq!(result, Err(PubkyNoiseError::HomeserverResponseError));
        assert_eq!(calls.get(), 3);
        assert_eq!(active.get(), 0);
    }

    #[tokio::test]
    async fn cancellation_stops_attempts_and_backoff() {
        let active = Cell::new(0);
        let calls = Cell::new(0);
        let policy = RequestPolicy {
            initial_backoff: Duration::from_secs(60),
            max_backoff: Duration::from_secs(60),
            ..policy(3)
        };
        let operation = policy.run(|| async {
            active.set(1);
            let _guard = ActiveAttempt(&active);
            calls.set(calls.get() + 1);
            pending::<Result<(), PubkyNoiseError>>().await
        });
        assert!(tokio::time::timeout(Duration::from_millis(50), operation)
            .await
            .is_err());
        assert_eq!(active.get(), 0, "the timed-out request survived backoff");
        assert_eq!(calls.get(), 1);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(calls.get(), 1, "cancellation spawned a background retry");
    }

    #[tokio::test]
    async fn retries_back_off_and_stop_after_success() {
        let mut starts = Vec::new();
        let result = policy(5)
            .run(|| {
                starts.push(Instant::now());
                std::future::ready(if starts.len() < 4 {
                    Err(PubkyNoiseError::HomeserverHttpError { status: 503 })
                } else {
                    Ok(42)
                })
            })
            .await;
        assert_eq!(result, Ok(42));
        assert_eq!(starts.len(), 4);
        for (pair, minimum) in starts.windows(2).zip([5, 10, 10]) {
            assert!(pair[1].duration_since(pair[0]) >= Duration::from_millis(minimum));
        }
    }

    #[tokio::test]
    async fn one_attempt_disables_retries() {
        let calls = Cell::new(0);
        let result: Result<(), _> = policy(1)
            .run(|| {
                calls.set(calls.get() + 1);
                pending::<Result<(), PubkyNoiseError>>()
            })
            .await;
        assert_eq!(result, Err(PubkyNoiseError::HomeserverResponseError));
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn maximum_attempt_count_returns_the_last_error() {
        let calls = Cell::new(0usize);
        let policy = RequestPolicy {
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            ..policy(u8::MAX)
        };
        let result: Result<(), _> = policy
            .run(|| {
                let attempt = calls.get() + 1;
                calls.set(attempt);
                let status = if attempt == usize::from(u8::MAX) {
                    504
                } else {
                    503
                };
                std::future::ready(Err(PubkyNoiseError::HomeserverHttpError { status }))
            })
            .await;
        assert_eq!(
            result,
            Err(PubkyNoiseError::HomeserverHttpError { status: 504 })
        );
        assert_eq!(calls.get(), usize::from(u8::MAX));
    }
}
