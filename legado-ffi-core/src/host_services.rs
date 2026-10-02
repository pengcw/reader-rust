//! Optional synchronous host capabilities. Registration is thread- and process-local.
//! The host owns callback/user_data until it unregisters; Rust owns response buffers.
use safer_ffi::prelude::*;
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::ffi::{c_void, CString};

pub const HOST_ABI_VERSION: u32 = 1;
pub const DEFAULT_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Return the number of UTF-8 JSON bytes written (no terminator required).
/// Negative values: -1 callback failure, -2 insufficient output capacity.
/// The callback must not unwind, yield, retain pointers, or re-enter the reader.
pub type HostCall = unsafe extern "C" fn(
    user_data: *mut c_void,
    operation: *const safer_ffi::c_char,
    arguments_json: *const safer_ffi::c_char,
    output: *mut u8,
    output_capacity: usize,
) -> i32;

#[derive_ReprC]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReaderHostServices {
    pub abi_version: u32,
    pub call: Option<HostCall>,
    pub user_data: *mut c_void,
    /// Zero selects 64 KiB. Maximum is 8 MiB. Calls are never replayed to resize.
    pub max_response_bytes: usize,
}

#[derive(Clone, Copy)]
struct Registration {
    services: ReaderHostServices,
    pid: u32,
}

thread_local! {
    static SERVICES: Cell<Option<Registration>> = const { Cell::new(None) };
    static IN_CALLBACK: Cell<bool> = const { Cell::new(false) };
    static RESPONSE_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static OFFLINE: Cell<bool> = const { Cell::new(false) };
}

/// 0 = success; -1 = invalid version/callback/limit; -2 = callback in progress.
/// NULL unregisters. Registration must be repeated in each worker after fork.
/// # Safety
/// Callback and user_data must remain valid in this thread until unregistering.
/// The callback must obey HostCall's buffer, threading and non-unwinding contract.
pub(crate) unsafe fn set(services: Option<&ReaderHostServices>) -> i32 {
    if in_callback() {
        return -2;
    }
    let registration = match services {
        Some(services) => {
            if services.abi_version != HOST_ABI_VERSION
                || services.call.is_none()
                || services.max_response_bytes > MAX_RESPONSE_BYTES
            {
                return -1;
            }
            let mut services = *services;
            if services.max_response_bytes == 0 {
                services.max_response_bytes = DEFAULT_RESPONSE_BYTES;
            }
            Some(Registration {
                services,
                pid: std::process::id(),
            })
        }
        None => None,
    };
    SERVICES.with(|slot| slot.set(registration));
    RESPONSE_BUFFER.with(|buffer| {
        // Drop sensitive scratch data and retained capacity when changing providers.
        buffer.borrow_mut().fill(0);
        *buffer.borrow_mut() = Vec::new();
    });
    0
}

pub fn in_callback() -> bool {
    IN_CALLBACK.with(Cell::get)
}

pub(crate) fn is_offline() -> bool {
    OFFLINE.with(Cell::get)
}

pub(crate) fn with_offline<T>(run: impl FnOnce() -> T) -> T {
    struct Guard(bool);
    impl Drop for Guard {
        fn drop(&mut self) {
            OFFLINE.with(|flag| flag.set(self.0));
        }
    }
    let _guard = Guard(OFFLINE.with(|flag| flag.replace(true)));
    run()
}

fn error(kind: &str, message: &str) -> Value {
    json!({"ok":false,"error":{"kind":kind,"message":message}})
}

struct CallbackGuard;
impl Drop for CallbackGuard {
    fn drop(&mut self) {
        IN_CALLBACK.with(|flag| flag.set(false));
    }
}

/// Return a JSON envelope. Never fall back after an executed provider operation.
pub fn call(operation: &str, arguments: &Value) -> Value {
    if is_offline() {
        return error(
            "permission_denied",
            "host services are disabled in offline diagnostics",
        );
    }
    if in_callback() {
        return error(
            "host_reentrant",
            "host callbacks cannot re-enter the reader",
        );
    }
    if operation.is_empty()
        || operation.len() > 128
        || !operation
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        return error("invalid_argument", "invalid host operation name");
    }
    let Some(registration) = SERVICES
        .with(Cell::get)
        .filter(|registration| registration.pid == std::process::id())
    else {
        return error(
            "unavailable",
            "host services are not registered in this thread/process",
        );
    };
    let operation = CString::new(operation).expect("validated operation has no NUL");
    let arguments = CString::new(arguments.to_string()).expect("JSON escapes NUL");
    IN_CALLBACK.with(|flag| flag.set(true));
    let _guard = CallbackGuard;
    RESPONSE_BUFFER.with(|buffer| {
        let mut buffer = buffer.borrow_mut();
        buffer.resize(registration.services.max_response_bytes, 0);
        let callback = registration.services.call.expect("validated callback");
        // SAFETY: the trusted host keeps callback/user_data alive until unregistering.
        // All buffers remain valid throughout this synchronous, non-reentrant callback.
        let length = unsafe {
            callback(
                registration.services.user_data,
                operation.as_ptr().cast(),
                arguments.as_ptr().cast(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        let result = if length == -2 || length > buffer.len() as i32 {
            error(
                "response_too_large",
                "host response exceeds configured capacity",
            )
        } else if length < 0 {
            error("host_failure", "host callback failed")
        } else {
            match serde_json::from_slice::<Value>(&buffer[..length as usize]) {
                Ok(value) if valid_envelope(&value) => value,
                _ => error("invalid_response", "host returned an invalid JSON envelope"),
            }
        };
        buffer.fill(0);
        result
    })
}

fn valid_envelope(value: &Value) -> bool {
    match value.get("ok").and_then(Value::as_bool) {
        Some(true) => value.get("data").is_some(),
        Some(false) => value.get("error").is_some_and(|error| {
            error.get("kind").and_then(Value::as_str).is_some()
                && error.get("message").and_then(Value::as_str).is_some()
        }),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn set(services: Option<&ReaderHostServices>) -> i32 {
        // Tests use static callbacks, null user_data and unregister before returning.
        unsafe { super::set(services) }
    }

    unsafe extern "C" fn echo(
        _: *mut c_void,
        operation: *const safer_ffi::c_char,
        args: *const safer_ffi::c_char,
        output: *mut u8,
        capacity: usize,
    ) -> i32 {
        let operation = unsafe { CStr::from_ptr(operation.cast()) }
            .to_str()
            .unwrap();
        let args: Value =
            serde_json::from_slice(unsafe { CStr::from_ptr(args.cast()) }.to_bytes()).unwrap();
        let value = if operation == "test.reentry" {
            assert_eq!(set(None), -2);
            call("test.echo", &json!({}))
        } else {
            json!({"ok":true,"data":args})
        };
        let bytes = value.to_string();
        if bytes.len() > capacity {
            return -2;
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
        bytes.len() as i32
    }
    fn services() -> ReaderHostServices {
        ReaderHostServices {
            abi_version: 1,
            call: Some(echo),
            user_data: std::ptr::null_mut(),
            max_response_bytes: 0,
        }
    }
    #[test]
    fn registration_call_clear_and_thread_isolation() {
        set(None);
        assert_eq!(
            call("test.echo", &json!({}))["error"]["kind"],
            "unavailable"
        );
        assert_eq!(set(Some(&services())), 0);
        assert_eq!(
            call("test.echo", &json!({"text":"中\u{0}文"}))["data"]["text"],
            "中\u{0}文"
        );
        assert_eq!(
            std::thread::spawn(|| call("test.echo", &json!({})))
                .join()
                .unwrap()["error"]["kind"],
            "unavailable"
        );
        assert_eq!(
            call("test.reentry", &json!({}))["error"]["kind"],
            "host_reentrant"
        );
        set(None);
        assert_eq!(
            call("test.echo", &json!({}))["error"]["kind"],
            "unavailable"
        );
    }
    #[test]
    fn js_bridge_and_offline_policy() {
        set(Some(&services()));
        assert_eq!(
            crate::parser::js::eval_js("java.hostCall('test.echo', {text:'你好'}).text", "", "")
                .unwrap(),
            "你好"
        );
        with_offline(|| {
            assert_eq!(
                call("test.echo", &json!({}))["error"]["kind"],
                "permission_denied"
            );
            with_offline(|| assert!(is_offline()));
            assert!(is_offline());
        });
        assert!(!is_offline());
        set(None);
        assert!(crate::parser::js::eval_js("java.hostCall('test.echo', {})", "", "").is_err());
    }
    #[test]
    fn validates_version_capacity_and_inherited_registration() {
        let mut config = services();
        config.abi_version = 2;
        assert_eq!(set(Some(&config)), -1);
        config = services();
        config.max_response_bytes = MAX_RESPONSE_BYTES + 1;
        assert_eq!(set(Some(&config)), -1);
        config = services();
        config.max_response_bytes = 1;
        set(Some(&config));
        assert_eq!(
            call("test.echo", &json!({}))["error"]["kind"],
            "response_too_large"
        );
        SERVICES.with(|slot| {
            let mut r = slot.get().unwrap();
            r.pid = r.pid.wrapping_add(1);
            slot.set(Some(r));
        });
        assert_eq!(
            call("test.echo", &json!({}))["error"]["kind"],
            "unavailable"
        );
        set(None);
    }
    #[test]
    fn rejects_invalid_provider_responses_without_retrying() {
        unsafe extern "C" fn invalid(
            _: *mut c_void,
            _: *const safer_ffi::c_char,
            _: *const safer_ffi::c_char,
            output: *mut u8,
            _: usize,
        ) -> i32 {
            unsafe {
                *output = b'!';
            }
            1
        }
        let mut config = services();
        config.call = Some(invalid);
        set(Some(&config));
        assert_eq!(
            call("test.echo", &json!({}))["error"]["kind"],
            "invalid_response"
        );
        assert_eq!(
            call("bad operation", &json!({}))["error"]["kind"],
            "invalid_argument"
        );
        set(None);
    }
}
