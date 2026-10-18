//! Internal evaluator budget. No host ABI or JavaScript pause API is exposed.
//! Measures active elapsed time, not thread CPU time. Only trusted host code may pause it.
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BudgetError {
    ComputeExpired,
    WaitExpired,
    AlreadyWaiting,
    InvalidToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WaitToken {
    generation: u64,
    sequence: u64,
}

pub(super) struct Budget {
    generation: u64,
    sequence: u64,
    checkpoint: Instant,
    compute_used: Duration,
    wait_used: Duration,
    compute_limit: Duration,
    wait_limit: Duration,
    waiting: Option<WaitToken>,
    expired: Option<BudgetError>,
}

impl Budget {
    pub(super) fn new(
        generation: u64,
        now: Instant,
        compute_limit: Duration,
        wait_limit: Duration,
    ) -> Self {
        Self {
            generation,
            sequence: 0,
            checkpoint: now,
            compute_used: Duration::ZERO,
            wait_used: Duration::ZERO,
            compute_limit,
            wait_limit,
            waiting: None,
            expired: None,
        }
    }

    // Every call supplies a monotonic instant from the owning evaluation thread.
    // Explicit instants make all boundary tests deterministic without sleeping.
    fn account(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.checkpoint);
        self.checkpoint = now;
        if self.waiting.is_some() {
            self.wait_used = self.wait_used.saturating_add(elapsed);
        } else {
            self.compute_used = self.compute_used.saturating_add(elapsed);
        }
        if self.expired.is_none() {
            if self.compute_used >= self.compute_limit {
                self.expired = Some(BudgetError::ComputeExpired);
            } else if self.wait_used >= self.wait_limit {
                self.expired = Some(BudgetError::WaitExpired);
            }
        }
    }

    pub(super) fn check(&mut self, now: Instant) -> Result<(), BudgetError> {
        self.account(now);
        self.expired.map_or(Ok(()), Err)
    }

    pub(super) fn begin_wait(&mut self, now: Instant) -> Result<WaitToken, BudgetError> {
        self.check(now)?;
        if self.waiting.is_some() {
            return Err(BudgetError::AlreadyWaiting);
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("wait sequence overflow");
        let token = WaitToken {
            generation: self.generation,
            sequence: self.sequence,
        };
        self.waiting = Some(token);
        Ok(token)
    }

    pub(super) fn end_wait(&mut self, now: Instant, token: WaitToken) -> Result<(), BudgetError> {
        if self.waiting != Some(token) {
            return Err(BudgetError::InvalidToken);
        }
        self.account(now);
        // Even an expired wait must resume accounting; expiry remains sticky.
        self.waiting = None;
        self.expired.map_or(Ok(()), Err)
    }

    // Callback cleanup fallback when the host forgot to end its waiting interval.
    // This must be called at callback exit by the future integration guard.
    #[cfg(test)]
    pub(super) fn close_wait(&mut self, now: Instant) -> Result<(), BudgetError> {
        self.account(now);
        self.waiting = None;
        self.expired.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Instant, Budget) {
        let now = Instant::now();
        (
            now,
            Budget::new(1, now, Duration::from_millis(100), Duration::from_secs(10)),
        )
    }

    fn ms(now: Instant, millis: u64) -> Instant {
        now + Duration::from_millis(millis)
    }

    #[test]
    fn exact_compute_boundary_without_sleep() {
        let (now, mut budget) = fixture();
        assert_eq!(budget.check(ms(now, 99)), Ok(()));
        assert_eq!(budget.check(ms(now, 100)), Err(BudgetError::ComputeExpired));
        assert_eq!(
            budget.begin_wait(ms(now, 100)),
            Err(BudgetError::ComputeExpired)
        );
    }

    #[test]
    fn long_wait_is_excluded_but_prior_compute_is_not_reset() {
        let (now, mut budget) = fixture();
        let token = budget.begin_wait(ms(now, 30)).unwrap();
        assert_eq!(budget.check(ms(now, 5030)), Ok(()));
        assert_eq!(budget.end_wait(ms(now, 5030), token), Ok(()));
        assert_eq!(budget.check(ms(now, 5099)), Ok(()));
        assert_eq!(
            budget.check(ms(now, 5100)),
            Err(BudgetError::ComputeExpired)
        );
    }

    #[test]
    fn multiple_waits_share_compute_budget() {
        let (now, mut budget) = fixture();
        let first = budget.begin_wait(ms(now, 20)).unwrap();
        budget.end_wait(ms(now, 1020), first).unwrap();
        let second = budget.begin_wait(ms(now, 1050)).unwrap();
        budget.end_wait(ms(now, 2050), second).unwrap();
        assert_eq!(budget.check(ms(now, 2099)), Ok(()));
        assert_eq!(
            budget.check(ms(now, 2100)),
            Err(BudgetError::ComputeExpired)
        );
    }

    #[test]
    fn wait_limit_is_cumulative_and_expiry_is_sticky() {
        let (now, mut budget) = fixture();
        let first = budget.begin_wait(now).unwrap();
        budget.end_wait(ms(now, 6000), first).unwrap();
        let second = budget.begin_wait(ms(now, 6001)).unwrap();
        assert_eq!(
            budget.end_wait(ms(now, 10001), second),
            Err(BudgetError::WaitExpired)
        );
        assert!(budget.waiting.is_none());
        assert_eq!(
            budget.begin_wait(ms(now, 10002)),
            Err(BudgetError::WaitExpired)
        );
    }

    #[test]
    fn rejects_nested_duplicate_and_previous_generation_tokens() {
        let (now, mut budget) = fixture();
        let first = budget.begin_wait(now).unwrap();
        assert_eq!(
            budget.begin_wait(ms(now, 1)),
            Err(BudgetError::AlreadyWaiting)
        );
        budget.end_wait(ms(now, 2), first).unwrap();
        assert_eq!(
            budget.end_wait(ms(now, 2), first),
            Err(BudgetError::InvalidToken)
        );
        let second = budget.begin_wait(ms(now, 3)).unwrap();
        assert_eq!(
            budget.end_wait(ms(now, 4), first),
            Err(BudgetError::InvalidToken)
        );
        let mut next = Budget::new(2, now, Duration::from_secs(1), Duration::from_secs(1));
        let next_token = next.begin_wait(now).unwrap();
        assert_eq!(
            next.end_wait(ms(now, 4), second),
            Err(BudgetError::InvalidToken)
        );
        next.end_wait(ms(now, 5), next_token).unwrap();
        budget.end_wait(ms(now, 5), second).unwrap();
    }

    #[test]
    fn callback_cleanup_resumes_compute_without_resetting_usage() {
        let (now, mut budget) = fixture();
        let token = budget.begin_wait(ms(now, 40)).unwrap();
        budget.close_wait(ms(now, 1040)).unwrap();
        assert_eq!(
            budget.end_wait(ms(now, 1040), token),
            Err(BudgetError::InvalidToken)
        );
        assert_eq!(budget.check(ms(now, 1099)), Ok(()));
        assert_eq!(
            budget.check(ms(now, 1100)),
            Err(BudgetError::ComputeExpired)
        );
    }

    #[test]
    fn unmarked_host_work_remains_compute_time() {
        let (now, mut budget) = fixture();
        assert_eq!(budget.check(ms(now, 200)), Err(BudgetError::ComputeExpired));
        assert_eq!(
            budget.close_wait(ms(now, 201)),
            Err(BudgetError::ComputeExpired)
        );
        assert_eq!(budget.wait_used, Duration::ZERO);
    }
}
