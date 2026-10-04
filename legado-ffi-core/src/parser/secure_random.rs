use ring::rand::{SecureRandom, SystemRandom};

pub(crate) fn next_int(bound: i32) -> anyhow::Result<i32> {
    anyhow::ensure!(bound > 0, "positive SecureRandom bound required");
    let random = SystemRandom::new();
    sample_bounded(bound as u32, || {
        let mut bytes = [0; 4];
        random
            .fill(&mut bytes)
            .map_err(|_| anyhow::anyhow!("secure random source unavailable"))?;
        Ok(u32::from_ne_bytes(bytes))
    })
    .map(|value| value as i32)
}

fn sample_bounded(
    bound: u32,
    mut draw: impl FnMut() -> anyhow::Result<u32>,
) -> anyhow::Result<u32> {
    // Reject the incomplete final bucket instead of biasing small bounds with modulo.
    let range = 1u64 << 32;
    let limit = range - range % u64::from(bound);
    loop {
        let value = draw()?;
        if u64::from(value) < limit {
            return Ok(value % bound);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_bucket_is_rejected_before_modulo() {
        let mut values = [u32::MAX, u32::MAX - 5, 19].into_iter();
        assert_eq!(
            sample_bounded(10, || Ok(values.next().unwrap())).unwrap(),
            9
        );
        assert!(values.next().is_none());
    }

    #[test]
    fn exact_buckets_and_largest_java_bound_preserve_range() {
        assert_eq!(sample_bounded(1, || Ok(u32::MAX)).unwrap(), 0);
        assert_eq!(sample_bounded(2, || Ok(u32::MAX)).unwrap(), 1);
        assert_eq!(
            sample_bounded(i32::MAX as u32, || Ok(i32::MAX as u32 - 1)).unwrap(),
            i32::MAX as u32 - 1
        );
    }

    #[test]
    fn random_source_failure_is_propagated_after_rejection() {
        let mut calls = 0;
        let error = sample_bounded(10, || {
            calls += 1;
            if calls == 1 {
                Ok(u32::MAX)
            } else {
                anyhow::bail!("source failed")
            }
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "source failed");
        assert_eq!(calls, 2);
        assert!(next_int(0).is_err());
        assert!(next_int(-1).is_err());
    }
}
