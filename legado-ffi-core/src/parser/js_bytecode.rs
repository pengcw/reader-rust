//! Cache bytecode for bundled JavaScript bootstraps, with helpers for jsLib.
//! All nine fixed bootstraps reuse disk bytecode across tasks when the host
//! provides a cache root. Dynamic jsLib bytecode may be
//! cached only by an ActiveSession and released when its operation ends.
//! Every invocation uses a fresh QuickJS Context; never cache JSValues,
//! closures, globals or host bindings across Contexts.
use rquickjs::{qjs, Ctx, Value};
use std::{cell::RefCell, ffi::CString, sync::Arc, time::Instant};

#[derive(Default)]
pub(super) struct BytecodeTimings {
    pub(super) compile_us: u128,
    pub(super) read_us: u128,
    pub(super) eval_us: u128,
}

#[repr(usize)]
#[derive(Clone, Copy)]
pub(super) enum BootstrapSlot {
    Java,
    Source,
    XPath,
    Jsoup,
    Android,
    Security,
    Math,
    Des,
    Aes,
}

impl BootstrapSlot {
    fn source(self) -> &'static str {
        match self {
            Self::Java => include_str!("js_bootstrap_java.js"),
            Self::Source => include_str!("js_bootstrap_source.js"),
            Self::XPath => include_str!("js_bootstrap_xpath.js"),
            Self::Jsoup => include_str!("js_bootstrap_jsoup.js"),
            Self::Android => include_str!("js_bootstrap_android.js"),
            Self::Security => include_str!("js_security.js"),
            Self::Math => include_str!("js_math.js"),
            Self::Des => include_str!("js_des.js"),
            Self::Aes => include_str!("js_aes.js"),
        }
    }
}

thread_local! {
    // Each thread's QuickJS Runtime lasts for the thread's lifetime.
    // Keep only serialized bytes, not compiled Values tied to an old Context.
    static COMPILED: RefCell<[Option<Arc<[u8]>>; 9]> =
        RefCell::new(std::array::from_fn(|_| None));
}

// Fixed bootstraps share a disk cache; never accept book-source paths or bytecode.
// The source and QuickJS/build/target properties determine each filename.
const BOOTSTRAP_FILE_LIMIT: u64 = 4 * 1024 * 1024;

fn bootstrap_cache_file(dir: &std::path::Path, slot: BootstrapSlot) -> std::path::PathBuf {
    // Keep in sync with Cargo.toml's pinned rquickjs version on upgrades.
    const RQUICKJS_VERSION: &str = "=0.12.0";
    let identity = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|",
        RQUICKJS_VERSION,
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::mem::size_of::<usize>(),
        if cfg!(target_endian = "little") { "le" } else { "be" },
        cfg!(feature = "kindle-eglibc-2-12"),
        cfg!(debug_assertions),
    );
    let mut input = identity.into_bytes();
    input.extend_from_slice(slot.source().as_bytes());
    let hash = ring::digest::digest(&ring::digest::SHA256, &input);
    dir.join(format!("bootstrap-{}.qbc", hex::encode(hash.as_ref())))
}

fn load_bootstrap(file: &std::path::Path) -> Option<Arc<[u8]>> {
    let data = crate::crawler::script_cache::read_limited(file, BOOTSTRAP_FILE_LIMIT)?;
    if data.len() <= 36 || &data[..4] != b"QBC1" { return None; }
    let payload = &data[36..];
    let actual = ring::digest::digest(&ring::digest::SHA256, payload);
    (actual.as_ref() == &data[4..36]).then(|| Arc::from(payload))
}

fn save_bootstrap(file: &std::path::Path, bytes: &[u8]) {
    if bytes.len() + 36 > BOOTSTRAP_FILE_LIMIT as usize { return; }
    let Some(dir) = file.parent() else { return; };
    let mut data = Vec::with_capacity(bytes.len() + 36);
    data.extend_from_slice(b"QBC1");
    data.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    data.extend_from_slice(bytes);
    crate::crawler::script_cache::publish_bootstrap(dir, file, &data);
}

// Query the Lua host at most once per fresh set of fixed bootstraps.
pub(super) fn disk_directory() -> Option<std::path::PathBuf> {
    let missing = COMPILED.with(|cache| cache.borrow().iter().any(Option::is_none));
    missing.then(crate::crawler::script_cache::ScriptCache::from_host)
        .flatten()?.directory(true)
}

fn js_error(ctx: &Ctx<'_>) -> anyhow::Error {
    if let Some(exception) = ctx.catch().into_exception() {
        anyhow::anyhow!("JS Exception: {:?}", exception)
    } else {
        anyhow::anyhow!("JS bytecode error: Exception")
    }
}

pub(super) fn compile(ctx: &Ctx<'_>, source: &str) -> anyhow::Result<Arc<[u8]>> {
    let script = CString::new(source)?;
    let raw_ctx = ctx.as_raw().as_ptr();
    // SAFETY: source and filename remain live during this call.
    // Preserve the original sloppy global script, not strict/module semantics.
    let raw = unsafe {
        qjs::JS_Eval(
            raw_ctx,
            script.as_ptr(),
            source.len() as _,
            c"eval_script".as_ptr(),
            (qjs::JS_EVAL_TYPE_GLOBAL | qjs::JS_EVAL_FLAG_COMPILE_ONLY) as _,
        )
    };
    if unsafe { qjs::JS_IsException(raw) } {
        return Err(js_error(ctx));
    }
    // SAFETY: JS_Eval returned an owned bytecode value for this Context.
    let compiled = unsafe { Value::from_raw(ctx.clone(), raw) };
    anyhow::ensure!(
        unsafe { qjs::JS_VALUE_GET_TAG(compiled.as_raw()) } == qjs::JS_TAG_FUNCTION_BYTECODE,
        "fixed bootstrap did not compile to global bytecode"
    );
    let mut length = 0;
    // SAFETY: the compiled Value stays alive until JS_WriteObject finishes.
    let buffer = unsafe {
        qjs::JS_WriteObject(
            raw_ctx,
            &mut length,
            compiled.as_raw(),
            qjs::JS_WRITE_OBJ_BYTECODE as _,
        )
    };
    if buffer.is_null() {
        return Err(js_error(ctx));
    }
    // SAFETY: copy QuickJS-owned buffer and release using QuickJS's allocator.
    let bytes = unsafe {
        let bytes: Arc<[u8]> = Arc::from(std::slice::from_raw_parts(buffer, length as usize));
        qjs::js_free(raw_ctx, buffer.cast());
        bytes
    };
    Ok(bytes)
}

fn read_compiled<'js>(
    ctx: &Ctx<'js>,
    bytes: &[u8],
    timings: Option<&mut BytecodeTimings>,
) -> anyhow::Result<qjs::JSValue> {
    let started = timings.as_ref().map(|_| Instant::now());
    // Disk cache accepts only a trusted, size-bounded, checksum-verified payload.
    let raw = unsafe {
        qjs::JS_ReadObject(
            ctx.as_raw().as_ptr(),
            bytes.as_ptr(),
            bytes.len() as _,
            qjs::JS_READ_OBJ_BYTECODE as _,
        )
    };
    if let (Some(timings), Some(started)) = (timings, started) {
        timings.read_us += started.elapsed().as_micros();
    }
    if unsafe { qjs::JS_IsException(raw) } {
        Err(js_error(ctx))
    } else {
        Ok(raw) // owned by the caller; JS_EvalFunction consumes it
    }
}

fn eval_compiled<'js>(
    ctx: Ctx<'js>,
    compiled: qjs::JSValue,
    timings: Option<&mut BytecodeTimings>,
) -> anyhow::Result<Value<'js>> {
    let started = timings.as_ref().map(|_| Instant::now());
    // SAFETY: EvalFunction consumes the owned bytecode, even on error.
    // Do not retry once the script may have executed with side effects.
    let raw = unsafe { qjs::JS_EvalFunction(ctx.as_raw().as_ptr(), compiled) };
    if let (Some(timings), Some(started)) = (timings, started) {
        timings.eval_us += started.elapsed().as_micros();
    }
    if unsafe { qjs::JS_IsException(raw) } {
        Err(js_error(&ctx))
    } else {
        Ok(unsafe { Value::from_raw(ctx, raw) })
    }
}

pub(super) fn execute<'js>(
    ctx: Ctx<'js>,
    bytes: &[u8],
    mut timings: Option<&mut BytecodeTimings>,
) -> anyhow::Result<Value<'js>> {
    let compiled = read_compiled(&ctx, bytes, timings.as_deref_mut())?;
    eval_compiled(ctx, compiled, timings)
}

pub(super) fn eval<'js>(
    ctx: Ctx<'js>,
    slot: BootstrapSlot,
    dir: Option<&std::path::Path>,
    mut timings: Option<&mut BytecodeTimings>,
) -> anyhow::Result<Value<'js>> {
    let index = slot as usize;
    if let Some(bytes) = COMPILED.with(|cache| cache.borrow()[index].clone()) {
        return execute(ctx, &bytes, timings);
    }

    let cache_file = dir.map(|dir| bootstrap_cache_file(dir, slot));
    if let Some(bytes) = cache_file.as_deref().and_then(load_bootstrap) {
        // A ReadObject failure is safe to recover before EvalFunction begins.
        if let Ok(compiled) = read_compiled(&ctx, &bytes, timings.as_deref_mut()) {
            COMPILED.with(|cache| cache.borrow_mut()[index] = Some(bytes));
            return eval_compiled(ctx, compiled, timings);
        }
    }

    let compile_start = timings.as_ref().map(|_| Instant::now());
    let result = compile(&ctx, slot.source());
    if let Some(start) = compile_start {
        timings.as_deref_mut().unwrap().compile_us += start.elapsed().as_micros();
    }
    let bytes = result?;
    if let Some(file) = cache_file.as_deref() {
        save_bootstrap(file, &bytes);
    }
    // Keep only serialized bytecode, never Context-bound values.
    COMPILED.with(|cache| cache.borrow_mut()[index] = Some(bytes.clone()));
    execute(ctx, &bytes, timings)
}
