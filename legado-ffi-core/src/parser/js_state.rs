//! Scoped state shared by the JS facade, native callbacks, and one `reader_execute` run.
//!
//! Keep QuickJS runtime/context lifetime management in `js.rs`; this module owns only
//! orthogonal state such as login/click capture, infoMap, jsLib, and source context.

use crate::model::book_source::BookSource;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::cell::RefCell;

thread_local! {
    pub(super) static LOGIN_MESSAGES: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    pub(super) static LOGIN_PREVIEW: RefCell<Option<JsonValue>> = const { RefCell::new(None) };
    pub(super) static CLICK_BROWSER: RefCell<Option<Option<JsonValue>>> = const { RefCell::new(None) };
}

// Capture only during a source click; restore the outer scope even on unwind.
pub(crate) fn with_click_browser<T>(run: impl FnOnce() -> T) -> (T, Option<JsonValue>) {
    CLICK_BROWSER.with(|cell| crate::util::scoped::with_scoped_value(cell, Some(None), || {
        let result = run();
        (result, cell.borrow().as_ref().and_then(Clone::clone))
    }))
}

pub(crate) fn with_login_messages<T>(run: impl FnOnce() -> T) -> (T, Vec<String>, Option<JsonValue>) {
    struct Restore(Option<Vec<String>>, Option<JsonValue>);
    impl Drop for Restore {
        fn drop(&mut self) {
            LOGIN_MESSAGES.with(|slot| *slot.borrow_mut() = self.0.take());
            LOGIN_PREVIEW.with(|slot| *slot.borrow_mut() = self.1.take());
        }
    }

    let restore = Restore(
        LOGIN_MESSAGES.with(|slot| slot.replace(Some(Vec::new()))),
        LOGIN_PREVIEW.with(|slot| slot.replace(None)),
    );
    let result = run();
    let messages = LOGIN_MESSAGES.with(|slot| slot.borrow_mut().take().unwrap_or_default());
    let preview = LOGIN_PREVIEW.with(|slot| slot.borrow_mut().take());
    drop(restore);
    (result, messages, preview)
}

pub(super) fn capture_login_message(message: Option<rquickjs::Coerced<String>>) {
    if let Some(message) = message {
        LOGIN_MESSAGES.with(|slot| {
            if let Some(messages) = slot.borrow_mut().as_mut() {
                if messages.len() < 8 && !message.0.trim().is_empty() {
                    messages.push(message.0.chars().take(1024).collect());
                }
            }
        });
    }
}

pub(super) const MAX_INFO_MAP_BYTES: usize = 256 * 1024;
const MAX_INFO_MAP_ENTRIES: usize = 64;
const MAX_INFO_MAP_KEY_BYTES: usize = 1024;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InfoMapState {
    pub(crate) values: std::collections::BTreeMap<String, String>,
    pub(crate) need_save: bool,
    pub(crate) save_time: i32,
}

impl InfoMapState {
    pub(crate) fn from_value(value: JsonValue) -> anyhow::Result<Self> {
        let encoded = serde_json::to_vec(&value)?;
        anyhow::ensure!(
            encoded.len() <= MAX_INFO_MAP_BYTES,
            "infoMap state is too large"
        );
        let state: Self = serde_json::from_value(value)?;
        anyhow::ensure!(
            state.save_time >= 0,
            "infoMap saveTime must not be negative"
        );
        anyhow::ensure!(
            state.values.len() <= MAX_INFO_MAP_ENTRIES,
            "infoMap has too many entries"
        );
        anyhow::ensure!(
            state
                .values
                .keys()
                .all(|key| key.len() <= MAX_INFO_MAP_KEY_BYTES),
            "infoMap key is too large"
        );
        Ok(state)
    }
}

thread_local! {
    static ACTIVE_JS_INFO_MAP: RefCell<Option<InfoMapState>> = const { RefCell::new(None) };
    pub(super) static ACTIVE_JS_LIB: RefCell<Option<String>> = const { RefCell::new(None) };
    pub(super) static ACTIVE_JS_BOOK_SOURCE: RefCell<Option<BookSource>> = const { RefCell::new(None) };
}

pub fn with_js_lib<T>(js_lib: Option<&str>, f: impl FnOnce() -> T) -> T {
    ACTIVE_JS_LIB
        .with(|cell| crate::util::scoped::with_scoped_value(cell, js_lib.map(str::to_string), f))
}

pub(crate) fn with_js_info_map<T>(state: InfoMapState, f: impl FnOnce() -> T) -> (T, InfoMapState) {
    ACTIVE_JS_INFO_MAP.with(|cell| {
        crate::util::scoped::with_scoped_value(cell, Some(state), || {
            let result = f();
            (
                result,
                cell.borrow().as_ref().expect("scoped infoMap").clone(),
            )
        })
    })
}

pub(super) fn active_info_map_state() -> Option<InfoMapState> {
    ACTIVE_JS_INFO_MAP.with(|cell| cell.borrow().clone())
}

pub(super) fn update_active_info_map(state: InfoMapState) {
    ACTIVE_JS_INFO_MAP.with(|cell| *cell.borrow_mut() = Some(state));
}
