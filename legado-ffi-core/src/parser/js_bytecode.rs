//! Cache bytecode for bundled JavaScript bootstraps, with helpers for jsLib.
//! Bundled bootstraps are cached per thread; dynamic jsLib bytecode may be
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

pub(super) fn execute<'js>(
    ctx: Ctx<'js>,
    bytes: &[u8],
    mut timings: Option<&mut BytecodeTimings>,
) -> anyhow::Result<Value<'js>> {
    let raw_ctx = ctx.as_raw().as_ptr();
    let read_start = timings.as_ref().map(|_| Instant::now());
    // SAFETY: serialized bytecode was generated in this process using the
    // same QuickJS version, never read from an untrusted disk/network cache.
    let compiled = unsafe {
        qjs::JS_ReadObject(
            raw_ctx,
            bytes.as_ptr(),
            bytes.len() as _,
            qjs::JS_READ_OBJ_BYTECODE as _,
        )
    };
    if let Some(start) = read_start {
        timings.as_deref_mut().unwrap().read_us += start.elapsed().as_micros();
    }
    if unsafe { qjs::JS_IsException(compiled) } {
        return Err(js_error(&ctx));
    }
    let eval_start = timings.as_ref().map(|_| Instant::now());
    // SAFETY: EvalFunction consumes the owned ReadObject value even on error.
    // Do not retry scripts that may have produced side effects.
    let result = unsafe { qjs::JS_EvalFunction(raw_ctx, compiled) };
    if let Some(start) = eval_start {
        timings.as_deref_mut().unwrap().eval_us += start.elapsed().as_micros();
    }
    if unsafe { qjs::JS_IsException(result) } {
        Err(js_error(&ctx))
    } else {
        Ok(unsafe { Value::from_raw(ctx, result) })
    }
}

pub(super) fn eval<'js>(
    ctx: Ctx<'js>,
    slot: BootstrapSlot,
    mut timings: Option<&mut BytecodeTimings>,
) -> anyhow::Result<Value<'js>> {
    let index = slot as usize;
    let cached = COMPILED.with(|cache| cache.borrow()[index].clone());
    let bytes = match cached {
        Some(bytes) => bytes,
        None => {
            let compile_start = timings.as_ref().map(|_| Instant::now());
            let result = compile(&ctx, slot.source());
            if let Some(start) = compile_start {
                timings.as_deref_mut().unwrap().compile_us += start.elapsed().as_micros();
            }
            let bytes = result?;
            // Release borrow before executing JS and host callbacks.
            COMPILED.with(|cache| cache.borrow_mut()[index] = Some(bytes.clone()));
            bytes
        }
    };
    execute(ctx, &bytes, timings)
}
