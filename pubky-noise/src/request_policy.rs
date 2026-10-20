use std::future::Future;
use std::num::NonZeroU8;
use std::time::Duration;

use futures_util::future::{select, Either};
use futures_util::pin_mut;

use crate::PubkyNoiseError;

/// Bounds network work performed by Noise's convenience APIs.
///
/// Each attempt includes request preparation and response-body consumption.
/// Retries reuse the same resource and, for writes, the exact prepared bytes.
/// Missing messages, authorization failures and invalid packets are not retried.
/// Callers still own authorization, aggregate concurrency and durable recovery.
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
            timeout: Duration::from_secs(10),
            max_attempts: NonZeroU8::new(3).expect("three attempts is nonzero"),
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(2),
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
        for attempt in 1..=self.max_attempts.get() {
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
                None if attempt < self.max_attempts.get() => {
                    delay(backoff).await;
                    backoff = backoff.saturating_mul(2).min(self.max_backoff);
                }
                Some(Err(error)) if attempt < self.max_attempts.get() && retryable(&error) => {
                    delay(backoff).await;
                    backoff = backoff.saturating_mul(2).min(self.max_backoff);
                }
                None => return Err(PubkyNoiseError::HomeserverResponseError),
                Some(result) => return result,
            }
        }
        unreachable!("max_attempts is nonzero")
    }
}

fn retryable(error: &PubkyNoiseError) -> bool {
    matches!(
        error,
        PubkyNoiseError::HomeserverHttpError {
            status: 408 | 429 | 502 | 503 | 504
        }
    )
}

async fn delay(mut duration: Duration) {
    // Browser timers use signed 32-bit milliseconds. Split longer waits rather
    // than allowing them to wrap into immediate retries.
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
}
