use std::cell::RefCell;

/// Restore the previous value on return or unwind, without borrowing during `f`.
pub(crate) fn with_scoped_value<T, R>(cell: &RefCell<T>, value: T, f: impl FnOnce() -> R) -> R {
    struct Restore<'a, T> {
        cell: &'a RefCell<T>,
        previous: Option<T>,
    }

    impl<T> Drop for Restore<'_, T> {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                self.cell.replace(previous);
            }
        }
    }

    let _restore = Restore {
        cell,
        previous: Some(cell.replace(value)),
    };
    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn scoped_value_restores_nested_none_errors_and_unwind() {
        let cell = RefCell::new(None);
        with_scoped_value(&cell, Some("outer"), || {
            let result: Result<(), &str> = with_scoped_value(&cell, None, || {
                assert_eq!(*cell.borrow(), None);
                Err("expected")
            });
            assert_eq!(result, Err("expected"));
            assert_eq!(*cell.borrow(), Some("outer"));
            assert!(catch_unwind(AssertUnwindSafe(|| {
                with_scoped_value(&cell, Some("inner"), || panic!("expected"));
            }))
            .is_err());
            assert_eq!(*cell.borrow(), Some("outer"));
        });
        assert_eq!(*cell.borrow(), None);
        assert!(catch_unwind(AssertUnwindSafe(|| {
            with_scoped_value(&cell, Some("outer"), || panic!("expected"));
        }))
        .is_err());
        assert_eq!(*cell.borrow(), None);
    }
}
