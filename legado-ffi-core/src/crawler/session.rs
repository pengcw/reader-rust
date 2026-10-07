//! Backward-compatible session facade.
//!
//! Runtime session state lives in `crate::runtime::session`; this module keeps
//! the existing public `crawler::session` path stable for hosts and tests.

pub use crate::runtime::session::{
    current_active_session, with_active_session, ActiveSession, ExecuteSession,
};
