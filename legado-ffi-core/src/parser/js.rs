use crate::parser::js_budget::Budget;
use crate::parser::js_bytecode::{self, BootstrapSlot};
use crate::parser::js_compat::{
    java_base64_decode, java_base64_decode_bytes, java_base64_encode_bytes, java_bytes_to_str,
    java_digest_bytes, java_encode_uri, java_hmac_bytes, java_hmac_string_bytes, java_str_to_bytes,
    java_time_format, java_time_format_utc, java_to_num_chapter, java_to_url_json,
    json_value_to_string,
};
#[cfg(test)]
use crate::parser::js_http::with_js_http_clients;
pub(crate) use crate::parser::js_http::with_login_check_request;
use crate::parser::js_http::{
    active_login_check_request, decode_archive_text, java_analyzed_request_body,
    java_analyzed_request_response, java_analyzed_test_request_response, java_archive_input,
    java_init_login_url, java_login_response_headers, java_request_simple, java_request_simple_response,
    java_response_decode_text, java_retry_login_request, java_web_view, resolve_js_lib_entry,
    webview_user_agent,
};
#[cfg(test)]
use crate::parser::js_http::{HttpClient, ACTIVE_JS_HTTP_CONTEXT};
pub use crate::parser::js_state::with_js_lib;
use crate::parser::js_state::{
    active_info_map_state, capture_login_message, capture_open_url, update_active_info_map,
    ACTIVE_JS_BOOK_SOURCE, ACTIVE_JS_LIB, CLICK_BROWSER, LOGIN_MESSAGES, LOGIN_PREVIEW,
    MAX_INFO_MAP_BYTES,
};
pub(crate) use crate::parser::js_state::{
    with_click_browser, with_js_info_map, with_login_messages, with_relogin_request, InfoMapState,
};
pub use crate::parser::js_url::{
    eval_js_url, eval_js_url_template, eval_js_url_template_with_bindings,
    eval_js_url_template_with_headers, eval_js_url_with_bindings, eval_js_url_with_headers,
};
use crate::parser::jsonpath;
use crate::parser::rule_analyzer;
use crate::parser::rule_engine;
use crate::parser::source_regex;
use crate::parser::{dom, html};
use crate::runtime::session::current_active_session;
use crate::util::hash::md5_hex;
use crate::util::text::strip_whitespace;
use crate::util::uuid::generate_uuid_v4;
use aes::Aes128;
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rquickjs::context::EvalOptions;
use rquickjs::function::Func;
use rquickjs::{Context, Object, Runtime, Value};
use serde_json::Value as JsonValue;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static JS_KV: Lazy<Mutex<HashMap<String, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static JS_CACHE: Lazy<Mutex<HashMap<String, JsCacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static JS_LIB_CACHE: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
struct JsCacheEntry {
    value: String,
    expires_at: Option<Instant>,
}

static JS_DEVICE_ID: Lazy<String> = Lazy::new(|| {
    let mut map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = map.get("__device_id") {
        return existing.clone();
    }
    let generated = generate_uuid_v4();
    map.insert("__device_id".to_string(), generated.clone());
    generated
});
type Aes128CbcDecryptor = cbc::Decryptor<Aes128>;
type Aes128CbcEncryptor = cbc::Encryptor<Aes128>;

type SharedJsBudget = Arc<Mutex<Option<Budget>>>;
static BUDGET_GENERATION: AtomicU64 = AtomicU64::new(1);

struct TimerGuard(SharedJsBudget);
impl Drop for TimerGuard {
    fn drop(&mut self) {
        *self.0.lock().unwrap() = None;
    }
}

// Only the fixed native browser driver uses this; ordinary hostCall cannot pause.
pub(super) fn with_browser_host_wait<T>(run: impl FnOnce() -> T) -> anyhow::Result<T> {
    JS_ENV.with(|(_, budget)| {
        let token = {
            let mut state = budget.lock().unwrap();
            match state.as_mut() {
                Some(state) => Some(
                    state
                        .begin_wait(Instant::now())
                        .map_err(|error| anyhow::anyhow!("browser wait budget: {error:?}"))?,
                ),
                None => None,
            }
        };
        struct Resume(SharedJsBudget, Option<crate::parser::js_budget::WaitToken>);
        impl Drop for Resume {
            fn drop(&mut self) {
                if let Some(token) = self.1 {
                    if let Some(state) = self.0.lock().unwrap().as_mut() {
                        let _ = state.end_wait(Instant::now(), token);
                    }
                }
            }
        }
        let guard = Resume(budget.clone(), token);
        let result = run();
        drop(guard);
        if let Some(state) = budget.lock().unwrap().as_mut() {
            state
                .check(Instant::now())
                .map_err(|error| anyhow::anyhow!("browser wait budget: {error:?}"))?;
        }
        Ok(result)
    })
}

// Opt-in timing of the ordinary JS evaluator. No script contents, URLs, or
// bindings are logged. Leave context isolation unchanged.
static JS_PROFILE_ENABLED: Lazy<bool> =
    Lazy::new(|| std::env::var("LEGADO_JS_PROFILE").as_deref() == Ok("1"));
// Opt-in diagnostics for dynamic jsLib; normal requests use the operation-
// scoped cache when eligible and retain the original evaluator otherwise.
static JS_LIB_SPLIT_DIAG: Lazy<bool> =
    Lazy::new(|| std::env::var("LEGADO_JS_LIB_DIAG").as_deref() == Ok("split"));
static JS_LIB_CACHE_DIAG: Lazy<bool> =
    Lazy::new(|| std::env::var("LEGADO_JS_LIB_DIAG").as_deref() == Ok("cache"));
// Benchmark-only baseline for reader_execute. Normal requests use the
// operation-scoped cache; do not change their behavior.
static JS_LIB_BASELINE_DIAG: Lazy<bool> =
    Lazy::new(|| std::env::var("LEGADO_JS_LIB_DIAG").as_deref() == Ok("baseline"));
// One diagnostic sample per thread, off by default. Counts belong to the
// entire thread-local Runtime, not to individual JavaScript objects or slots.
static JS_MEMORY_PROFILE_ENABLED: Lazy<bool> =
    Lazy::new(|| std::env::var("LEGADO_JS_MEMORY_PROFILE").as_deref() == Ok("1"));

type JsMemorySample = (&'static str, rquickjs::qjs::JSMemoryUsage);

fn record_js_memory(
    samples: &mut Vec<JsMemorySample>,
    stage: &'static str,
    ctx: &rquickjs::Ctx<'_>,
) {
    if samples.is_empty() {
        return;
    }
    // SAFETY: Context::with holds the Runtime lock on this thread. Taking
    // Runtime::memory_usage() here would deadlock by reacquiring that lock.
    let mut usage = std::mem::MaybeUninit::uninit();
    unsafe {
        let runtime = rquickjs::qjs::JS_GetRuntime(ctx.as_raw().as_ptr());
        rquickjs::qjs::JS_ComputeMemoryUsage(runtime, usage.as_mut_ptr());
        samples.push((stage, usage.assume_init()));
    }
}

fn report_js_memory(samples: &[JsMemorySample]) {
    if let Some((stage, first)) = samples.first() {
        eprintln!("[legado::js_memory] stage={stage} used={} malloc={} objects={} props={} shapes={} atoms={} js_funcs={} c_funcs={}",
            first.memory_used_size, first.malloc_size, first.obj_count, first.prop_count,
            first.shape_count, first.atom_count, first.js_func_count, first.c_func_count);
    }
    for window in samples.windows(2) {
        let (_, before) = &window[0];
        let (stage, after) = &window[1];
        eprintln!("[legado::js_memory] stage={stage} delta_used={:+} delta_malloc={:+} delta_objects={:+} delta_props={:+} delta_shapes={:+} delta_atoms={:+} delta_js_funcs={:+} delta_c_funcs={:+}",
            after.memory_used_size - before.memory_used_size,
            after.malloc_size - before.malloc_size,
            after.obj_count - before.obj_count,
            after.prop_count - before.prop_count,
            after.shape_count - before.shape_count,
            after.atom_count - before.atom_count,
            after.js_func_count - before.js_func_count,
            after.c_func_count - before.c_func_count);
    }
}

#[derive(Default)]
struct JsProfileTotals {
    count: u64,
    micros: [u128; 7],
    setup_micros: [u128; 3],
    cleanup_micros: [u128; 2],
    slots_micros: [u128; 9],
    bytecode_phase_micros: [[u128; 9]; 3], // ReadObject, EvalFunction, cold compile
    lib_split_micros: [u128; 3],           // compile/serialize, bytecode read, execute
    lib_cache_hits: u64,
    lib_bytecode_bytes: usize,
    // Per JS invocation: native source, cookie/cache, java, then host parse/call/encode.
    bridge_micros: [u128; 6],
    bridge_calls: u64,
}

impl JsProfileTotals {
    fn add(
        &mut self,
        stages: [u128; 7],
        setup: [u128; 3],
        cleanup: [u128; 2],
        slots: [u128; 9],
        phases: [[u128; 9]; 3],
        lib_split: [u128; 3],
        lib_cache: (u64, usize),
        bridge: ([u128; 6], u64),
    ) {
        self.count += 1;
        for (total, elapsed) in self.micros.iter_mut().zip(stages) {
            *total += elapsed;
        }
        for (total, elapsed) in self.setup_micros.iter_mut().zip(setup) {
            *total += elapsed;
        }
        for (total, elapsed) in self.cleanup_micros.iter_mut().zip(cleanup) {
            *total += elapsed;
        }
        for (total, elapsed) in self.slots_micros.iter_mut().zip(slots) {
            *total += elapsed;
        }
        for (total, elapsed) in self.lib_split_micros.iter_mut().zip(lib_split) {
            *total += elapsed;
        }
        self.lib_cache_hits += lib_cache.0;
        self.lib_bytecode_bytes = self.lib_bytecode_bytes.max(lib_cache.1);
        self.bridge_calls += bridge.1;
        for (total, elapsed) in self.bridge_micros.iter_mut().zip(bridge.0) {
            *total += elapsed;
        }
        for (total_group, samples) in self.bytecode_phase_micros.iter_mut().zip(phases) {
            for (total, elapsed) in total_group.iter_mut().zip(samples) {
                *total += elapsed;
            }
        }
        if self.count.is_multiple_of(50) {
            let avg = |index: usize| self.micros[index] / self.count as u128;
            let setup_avg = |index: usize| self.setup_micros[index] / self.count as u128;
            let cleanup_avg = |index: usize| self.cleanup_micros[index] / self.count as u128;
            let slot_avg = |index: usize| self.slots_micros[index] / self.count as u128;
            eprintln!(
                "[legado::js_profile] calls={} avg_us context={} lib_lookup={} setup={} setup_script={} builtin_script={} dom={} setup_other={} lib_eval={} before_script={} script={} finish={} finish_drop={} finish_gc={} slot_java={} slot_source={} slot_xpath={} slot_jsoup={} slot_android={} slot_security={} slot_math={} slot_des={} slot_aes={}",
                self.count, avg(0), avg(1), avg(2), setup_avg(0), setup_avg(1),
                setup_avg(2), avg(2).saturating_sub(setup_avg(0) + setup_avg(1) + setup_avg(2)),
                avg(3), avg(4), avg(5), avg(6), cleanup_avg(0), cleanup_avg(1),
                slot_avg(0), slot_avg(1), slot_avg(2), slot_avg(3), slot_avg(4),
                slot_avg(5), slot_avg(6), slot_avg(7), slot_avg(8)
            );
            // Keep the existing profiler line stable for older diagnostic parsers.
            // Additional numeric-only line splits each fixed bootstrap phase.
            let mut line = format!("[legado::js_bytecode] calls={} avg_us", self.count);
            for (phase, values) in ["read", "eval", "compile"]
                .into_iter()
                .zip(&self.bytecode_phase_micros)
            {
                for (name, elapsed) in [
                    "java", "source", "xpath", "jsoup", "android", "security", "math", "des", "aes",
                ]
                .into_iter()
                .zip(values)
                {
                    use std::fmt::Write;
                    let _ = write!(line, " {phase}_{name}={}", elapsed / self.count as u128);
                }
            }
            eprintln!("{line}");
            let bridge_avg = |index: usize| self.bridge_micros[index] / self.count as u128;
            eprintln!(
                "[legado::js_bridge] calls={} avg_us source={} cookie_cache={} java={} host_parse={} host_call={} host_encode={} host_calls={}",
                self.count, bridge_avg(0), bridge_avg(1), bridge_avg(2),
                bridge_avg(3), bridge_avg(4), bridge_avg(5), self.bridge_calls
            );
            if *JS_LIB_SPLIT_DIAG || *JS_LIB_CACHE_DIAG {
                eprintln!(
                    "[legado::js_lib] calls={} avg_us compile={} read={} execute={} hits={} bytecode_bytes={}",
                    self.count, self.lib_split_micros[0] / self.count as u128,
                    self.lib_split_micros[1] / self.count as u128,
                    self.lib_split_micros[2] / self.count as u128,
                    self.lib_cache_hits, self.lib_bytecode_bytes,
                );
            }
        }
    }
}

fn js_bridge_mark(index: usize, started: Option<Instant>) {
    if let Some(started) = started {
        JS_BRIDGE_METRICS
            .with(|metrics| metrics.borrow_mut().0[index] += started.elapsed().as_micros());
    }
}

fn js_profile_mark(mark: &mut Option<Instant>, stages: &mut [u128; 7], index: usize) {
    if let Some(start) = mark.as_mut() {
        stages[index] = start.elapsed().as_micros();
        *start = Instant::now();
    }
}

fn eval_profiled_setup_script<'js>(
    ctx: rquickjs::Ctx<'js>,
    slot: BootstrapSlot,
    bucket: usize,
    dir: Option<&std::path::Path>,
) -> anyhow::Result<Value<'js>> {
    let mark = (*JS_PROFILE_ENABLED).then(Instant::now);
    let mut timings = js_bytecode::BytecodeTimings::default();
    let result = js_bytecode::eval(
        ctx,
        slot,
        dir,
        (*JS_PROFILE_ENABLED).then_some(&mut timings),
    );
    if let Some(mark) = mark {
        let elapsed = mark.elapsed().as_micros();
        JS_SETUP_METRICS.with(|totals| totals.borrow_mut()[bucket] += elapsed);
        JS_SETUP_SLOT_METRICS.with(|totals| totals.borrow_mut()[slot as usize] += elapsed);
        JS_BYTECODE_PHASE_METRICS.with(|totals| {
            let mut totals = totals.borrow_mut();
            let index = slot as usize;
            totals[0][index] += timings.read_us;
            totals[1][index] += timings.eval_us;
            totals[2][index] += timings.compile_us;
        });
    }
    result
}

fn eval_fixed_setup_script<'js>(
    ctx: rquickjs::Ctx<'js>,
    slot: BootstrapSlot,
    dir: Option<&std::path::Path>,
) -> anyhow::Result<Value<'js>> {
    eval_profiled_setup_script(ctx, slot, 0, dir)
}

fn eval_builtin_setup_script<'js>(
    ctx: rquickjs::Ctx<'js>,
    slot: BootstrapSlot,
    dir: Option<&std::path::Path>,
) -> anyhow::Result<Value<'js>> {
    eval_profiled_setup_script(ctx, slot, 1, dir)
}

thread_local! {
    static JS_SETUP_METRICS: RefCell<[u128; 3]> = const { RefCell::new([0; 3]) };
    static JS_SETUP_SLOT_METRICS: RefCell<[u128; 9]> = const { RefCell::new([0; 9]) };
    static JS_BYTECODE_PHASE_METRICS: RefCell<[[u128; 9]; 3]> = const { RefCell::new([[0; 9]; 3]) };
    static JS_LIB_SPLIT_METRICS: RefCell<[u128; 3]> = const { RefCell::new([0; 3]) };
    static JS_LIB_CACHE_STATS: RefCell<(u64, usize)> = const { RefCell::new((0, 0)) };
    static JS_BRIDGE_METRICS: RefCell<([u128; 6], u64)> = const { RefCell::new(([0; 6], 0)) };
    static JS_PROFILE_TOTALS: RefCell<JsProfileTotals> = RefCell::new(JsProfileTotals::default());
    static JS_MEMORY_PROFILE_SAMPLED: Cell<bool> = const { Cell::new(false) };
    // Native JS callbacks may need AnalyzeUrl to evaluate nested header/URL JavaScript.
    // Reuse the currently borrowed QuickJS context instead of entering Context::with again.
    static ACTIVE_JS_REENTRANT_CTX: RefCell<Option<NonNull<rquickjs::qjs::JSContext>>> =
        const { RefCell::new(None) };

    // Populated only while running an explicitly requested TOC pre-update hook.
    static PRE_UPDATE_TOC_SNAPSHOT: RefCell<Option<(String, String)>> = const { RefCell::new(None) };

    static JS_ENV: (Runtime, SharedJsBudget) = {
        // Missing preparation must fail compilation, never ship an unpatched engine.
        const { assert!(rquickjs::qjs::LEGADO_STRING_LENGTH_PATCH == 2) };
        let _: [(); 1] = [(); rquickjs::LEGADO_STRING_WRAPPER_PATCH];
        let rt = Runtime::new().expect("Failed to create JS Runtime");
        rt.set_max_stack_size(512 * 1024);
        rt.set_memory_limit(30 * 1024 * 1024);

        let start_time: SharedJsBudget = Arc::new(Mutex::new(None));
        let st_clone = start_time.clone();

        rt.set_interrupt_handler(Some(Box::new(move || {
            st_clone.lock().unwrap().as_mut()
                .is_some_and(|budget| budget.check(Instant::now()).is_err())
        })));

        (rt, start_time)
    };
}

fn request_call_timeout(
    ctx: &rquickjs::Ctx<'_>,
    timeout_ms: Option<u64>,
) -> rquickjs::Result<Option<Duration>> {
    match timeout_ms {
        None => Ok(None),
        Some(value @ 1..=120_000) => Ok(Some(Duration::from_millis(value))),
        Some(_) => Err(rquickjs::Exception::throw_type(
            ctx,
            "callTimeout must be an integer from 1 to 120000 milliseconds",
        )),
    }
}

fn with_js_reentrant_ctx<T>(ctx: &rquickjs::Ctx<'_>, f: impl FnOnce() -> T) -> T {
    ACTIVE_JS_REENTRANT_CTX
        .with(|cell| crate::util::scoped::with_scoped_value(cell, Some(ctx.as_raw()), f))
}

pub fn eval_js(script: &str, input: &str, base_url: &str) -> anyhow::Result<String> {
    eval_js_inner(script, Some(input), Some(base_url), None, None, None)
}

// Internal type metadata, never installed as a JavaScript global.
// Only execution paths that know an input is a Java Map may set it.
pub(crate) const JAVA_MAP_BINDINGS_KEY: &str = "__legadoJavaMapBindings";

pub fn eval_js_with_bindings(
    script: &str,
    input: &str,
    base_url: &str,
    bindings: &HashMap<String, JsonValue>,
) -> anyhow::Result<String> {
    eval_js_inner(
        script,
        Some(input),
        Some(base_url),
        None,
        None,
        Some(bindings),
    )
}

/// `refreshTocUrl()` can reuse the detail page already fetched by `execute_toc`.
/// The native callback is installed only for this scoped evaluation; JavaScript
/// cannot enable it by setting a global flag.
pub fn eval_js_toc_pre_update(
    script: &str,
    base_url: &str,
    bindings: &HashMap<String, JsonValue>,
    book_url: &str,
    refreshed_toc_url: &str,
) -> anyhow::Result<String> {
    PRE_UPDATE_TOC_SNAPSHOT.with(|slot| {
        crate::util::scoped::with_scoped_value(
            slot,
            Some((book_url.to_string(), refreshed_toc_url.to_string())),
            || eval_js_with_bindings(script, "", base_url, bindings),
        )
    })
}

pub fn eval_js_search_with_source(
    script: &str,
    key: &str,
    page: i32,
    source_key: &str,
) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script,
        None,
        None,
        Some(key),
        Some(page),
        Some(source_key),
        None,
        false,
        None,
    )
}

pub fn eval_js_template(script: &str, input: &str, base_url: &str) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script,
        Some(input),
        Some(base_url),
        None,
        None,
        None,
        None,
        true,
        None,
    )
}

pub fn eval_js_template_with_bindings(
    script: &str,
    input: &str,
    base_url: &str,
    bindings: &HashMap<String, JsonValue>,
) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script,
        Some(input),
        Some(base_url),
        None,
        None,
        None,
        Some(bindings),
        true,
        None,
    )
}

fn eval_js_inner(
    script: &str,
    input: Option<&str>,
    base_url: Option<&str>,
    key: Option<&str>,
    page: Option<i32>,
    bindings: Option<&HashMap<String, JsonValue>>,
) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script, input, base_url, key, page, None, bindings, false, None,
    )
}

fn install_header_map<'js>(
    ctx: &rquickjs::Ctx<'js>,
    java: &Object<'js>,
    initial: &serde_json::Map<String, JsonValue>,
) -> anyhow::Result<()> {
    java.set(
        "headerMap",
        ctx.json_parse(JsonValue::Object(initial.clone()).to_string())?,
    )?;
    eval_script(
        ctx.clone(),
        r#"(function(map) {
        Object.defineProperties(map, {
            put: { value: function(key, value) {
                const previous = this[key]; this[key] = String(value); return previous;
            } },
            get: { value: function(key) { return this[key] ?? null; } },
            remove: { value: function(key) {
                const previous = this[key]; delete this[key]; return previous;
            } }
        });
    })(java.headerMap)"#,
    )?;
    Ok(())
}

fn install_info_map<'js>(ctx: &rquickjs::Ctx<'js>, state: &InfoMapState) -> anyhow::Result<()> {
    ctx.globals().set(
        "__readerInfoMapInitial",
        ctx.json_parse(serde_json::to_string(state)?)?,
    )?;
    eval_script(
        ctx.clone(),
        r#"(() => {
            const initial = globalThis.__readerInfoMapInitial;
            delete globalThis.__readerInfoMapInitial;
            let backing = new Map(Object.entries(initial.values));
            let needSave = initial.needSave;
            let saveTime = initial.saveTime;
            const views = new WeakMap();
            const entriesOf = value => {
                if (value instanceof Map) return Array.from(value.entries());
                if (value && typeof value === 'object' && views.has(value)) {
                    return Array.from(views.get(value)().entries());
                }
                if (!value || typeof value !== 'object' || Array.isArray(value)) {
                    throw new TypeError('infoMap.set expects a map or object');
                }
                return Object.keys(value).map(key => [key, value[key]]);
            };
            // The root follows replacement; returned views keep their original Map.
            const makeView = current => {
                const view = Object.create(null);
                views.set(view, current);
                const put = (key, value) => {
                    const target = current();
                    key = String(key); value = String(value);
                    const previous = target.has(key) ? target.get(key) : null;
                    target.set(key, value); return previous;
                };
                Object.defineProperties(view, {
                    size: { get: () => current().size },
                    get: { configurable: true, value: key => current().has(String(key)) ? current().get(String(key)) : null },
                    put: { value: put },
                    set: { configurable: true, value: put },
                    remove: { value: key => {
                        const target = current();
                        key = String(key);
                        const previous = target.has(key) ? target.get(key) : null;
                        target.delete(key); return previous;
                    } },
                    putAll: { value: value => { for (const [key, item] of entriesOf(value)) put(key, item); } },
                    containsKey: { value: key => current().has(String(key)) },
                    containsValue: { value: value => Array.from(current().values()).includes(String(value)) },
                    isEmpty: { value: () => current().size === 0 },
                    clear: { value: () => current().clear() }
                });
                return view;
            };
            const api = makeView(() => backing);
            const snapshot = () => ({ values: Object.fromEntries(backing), needSave, saveTime });
            const get = api.get;
            Object.defineProperties(api, {
                get: { value: function(key) {
                    const target = backing;
                    return arguments.length === 0 ? makeView(() => target) : get(key);
                } },
                set: { value: value => { backing = new Map(entriesOf(value).map(([key, item]) => [String(key), String(item)])); } },
                save: { value: function(time, need) {
                    time = arguments.length > 0 ? time : 0;
                    need = arguments.length > 1 ? need : true;
                    if (!Number.isInteger(time) || time < 0 || time > 2147483647) {
                        throw new RangeError('infoMap saveTime must be a non-negative 32-bit integer');
                    }
                    if (typeof need !== 'boolean') throw new TypeError('infoMap needSave must be boolean');
                    saveTime = time; needSave = need;
                } },
                saveNow: { value: () => {
                    const response = JSON.parse(java.__infoMapSaveNow(JSON.stringify(snapshot())));
                    if (!response.ok) {
                        needSave = true;
                        const error = new Error(response.error.message);
                        error.kind = response.error.kind; throw error;
                    }
                    needSave = false;
                } }
            });
            Object.defineProperty(globalThis, 'infoMap', {
                configurable: true, enumerable: true, writable: true, value: api
            });
            Object.defineProperty(java, '__infoMapSnapshot', {
                configurable: false, enumerable: false, writable: false,
                value: () => JSON.stringify(snapshot())
            });
        })();"#,
    )?;
    Ok(())
}

fn collect_header_map(ctx: &rquickjs::Ctx<'_>) -> anyhow::Result<Vec<(String, String)>> {
    let map = eval_script(ctx.clone(), "java.headerMap")?;
    let json = ctx
        .json_stringify(map)?
        .ok_or_else(|| anyhow::anyhow!("invalid java.headerMap"))?;
    let values: serde_json::Map<String, JsonValue> = serde_json::from_str(&json.to_string()?)?;
    Ok(values
        .into_iter()
        .filter_map(|(key, value)| value.as_str().map(|value| (key, value.to_owned())))
        .collect())
}

// Convert only source bindings explicitly tagged by the executor as Java Maps.
// Keep the tag private to Rust; do not expose it to book-source JavaScript.
fn install_explicit_java_map_bindings<'js>(
    ctx: &rquickjs::Ctx<'js>,
    bindings: Option<&HashMap<String, JsonValue>>,
) -> anyhow::Result<()> {
    let Some(bindings) = bindings else {
        return Ok(());
    };
    let Some(names) = bindings.get(JAVA_MAP_BINDINGS_KEY) else {
        return Ok(());
    };
    let names = names
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid Java Map binding metadata"))?;
    let globals = ctx.globals();
    let adapter: rquickjs::Function<'js> =
        globals.get::<_, Object<'js>>("java")?.get("__asJavaMap")?;
    for name in names {
        let name = name
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid Java Map binding name"))?;
        if !bindings.get(name).is_some_and(JsonValue::is_object) {
            anyhow::bail!("Java Map binding must be an object: {name}");
        }
        let value: Value<'js> = globals.get(name)?;
        globals.set(name, adapter.call::<_, Value<'js>>((value,))?)?;
    }
    Ok(())
}

type HeaderMapContext<'a> = (
    &'a serde_json::Map<String, JsonValue>,
    &'a std::cell::RefCell<Option<Vec<(String, String)>>>,
);

pub(super) fn eval_js_inner_with_source(
    script: &str,
    input: Option<&str>,
    base_url: Option<&str>,
    key: Option<&str>,
    page: Option<i32>,
    source_key: Option<&str>,
    bindings: Option<&HashMap<String, JsonValue>>,
    template_result: bool,
    header_map: Option<HeaderMapContext<'_>>,
) -> anyhow::Result<String> {
    if let Some(raw_ctx) = ACTIVE_JS_REENTRANT_CTX.with(|cell| *cell.borrow()) {
        // SAFETY: the pointer is installed only for the duration of a native
        // callback invoked by this same QuickJS context and thread.
        let ctx = unsafe { rquickjs::Ctx::from_raw(raw_ctx) };
        if let Some((initial, updated)) = header_map {
            let java: Object<'_> = ctx.globals().get("java")?;
            let original = if java.contains_key("headerMap")? {
                Some(java.get::<_, Value<'_>>("headerMap")?)
            } else {
                None
            };
            let result = (|| {
                install_header_map(&ctx, &java, initial)?;
                let result = eval_js_reentrant(
                    ctx.clone(),
                    script,
                    input,
                    base_url,
                    key,
                    page,
                    source_key,
                    bindings,
                    template_result,
                )?;
                *updated.borrow_mut() = Some(collect_header_map(&ctx)?);
                Ok(result)
            })();
            match original {
                Some(value) => {
                    let _ = java.set("headerMap", value);
                }
                None => {
                    let _ = java.remove("headerMap");
                }
            }
            return result;
        }
        return eval_js_reentrant(
            ctx,
            script,
            input,
            base_url,
            key,
            page,
            source_key,
            bindings,
            template_result,
        );
    }

    let bootstrap_dir = js_bytecode::disk_directory();
    JS_ENV.with(|(runtime, start_time)| {
        let mut profile_mark = (*JS_PROFILE_ENABLED).then(Instant::now);
        let mut profile_stages = [0u128; 7];
        let mut profile_cleanup = [0u128; 2];
        if *JS_PROFILE_ENABLED {
            JS_SETUP_METRICS.with(|totals| *totals.borrow_mut() = [0; 3]);
            JS_SETUP_SLOT_METRICS.with(|totals| *totals.borrow_mut() = [0; 9]);
            JS_BYTECODE_PHASE_METRICS.with(|totals| *totals.borrow_mut() = [[0; 9]; 3]);
            JS_LIB_SPLIT_METRICS.with(|totals| *totals.borrow_mut() = [0; 3]);
            JS_LIB_CACHE_STATS.with(|stats| *stats.borrow_mut() = (0, 0));
            JS_BRIDGE_METRICS.with(|metrics| *metrics.borrow_mut() = ([0; 6], 0));
        }
        let mut memory_samples: Vec<JsMemorySample> = Vec::new();
        if *JS_MEMORY_PROFILE_ENABLED
            && JS_MEMORY_PROFILE_SAMPLED.with(|sampled| !sampled.replace(true))
        {
            memory_samples.push(("runtime_before", runtime.memory_usage()));
        }
        // A fresh context prevents top-level `const` in jsLib from being
        // redeclared and keeps implicit JS globals out of other sources.
        // Native callbacks still reuse this context through ACTIVE_JS_REENTRANT_CTX.
        let ctx = Context::full(runtime)?;
        if !memory_samples.is_empty() {
            memory_samples.push(("context", runtime.memory_usage()));
        }
        js_profile_mark(&mut profile_mark, &mut profile_stages, 0);
        *start_time.lock().unwrap() = Some(Budget::new(
            BUDGET_GENERATION.fetch_add(1, Ordering::Relaxed), Instant::now(),
            Duration::from_secs(4), Duration::from_secs(120),
        ));
        let _guard = TimerGuard(start_time.clone());
        let eval_result = ctx.with(|ctx| {
            let globals = ctx.globals();
            let input_value = input.unwrap_or("");
            let content_state = Arc::new(Mutex::new(input_value.to_string()));
            let base_url_value = base_url.unwrap_or("");
            let base_url_state = Arc::new(Mutex::new(base_url_value.to_string()));
            let variable_overrides = Arc::new(Mutex::new(HashMap::<String, String>::new()));
            let shared_js = active_js_lib_script()?;
            js_profile_mark(&mut profile_mark, &mut profile_stages, 1);

            globals.set("input", input_value)?;
            globals.set("result", input_value)?;
            globals.set("src", input_value)?;
            globals.set("loginInfo", ctx.json_parse("null")?)?;
            globals.set("base_url", base_url_value)?;
            globals.set("baseUrl", base_url_value)?;
            if let Some(key) = key {
                globals.set("key", key)?;
            }
            if let Some(page) = page {
                globals.set("page", page)?;
            }

            // Default url variable for Legado compatibility
            globals.set("url", base_url_value)?;

            // Stubs for Legado compatibility
            let source_key_val = source_key
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .or_else(|| {
                    ACTIVE_JS_BOOK_SOURCE.with(|cell| {
                        cell.borrow()
                            .as_ref()
                            .map(|source| source.book_source_url.clone())
                    })
                })
                .unwrap_or_default();
            // Segment totals are an upper bound for registration: they also
            // include object setup and captured state, not only Func::new.
            let native_mark = (*JS_PROFILE_ENABLED).then(Instant::now);
            let source_obj = Object::new(ctx.clone())?;
            let sk_clone = source_key_val.clone();
            source_obj.set("key", source_key_val.clone())?;
            source_obj.set("getKey", Func::new(move || sk_clone.clone()))?;
            source_obj.set(
                "__getHeaderMap",
                Func::new(|ctx: rquickjs::Ctx<'_>, include_login: bool| -> rquickjs::Result<String> {
                    let source = ACTIVE_JS_BOOK_SOURCE.with(|slot| slot.borrow().clone())
                        .unwrap_or_default();
                    let headers = with_js_reentrant_ctx(&ctx, || {
                        crate::crawler::source_header_map(&source, include_login)
                    });
                    serde_json::to_string(&headers)
                        .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error.to_string()))
                }),
            )?;
            if let Some(active_source) = ACTIVE_JS_BOOK_SOURCE.with(|cell| cell.borrow().clone()) {
                source_obj.set("bookSourceUrl", active_source.book_source_url)?;
                source_obj.set("bookSourceName", active_source.book_source_name)?;
                source_obj.set("bookSourceComment", ctx.json_parse(
                    serde_json::to_string(&active_source.book_source_comment)?,
                )?)?;
                source_obj.set("lastUpdateTime", active_source.last_update_time.unwrap_or(0))?;
                source_obj.set("header", active_source.header.unwrap_or_default())?;
                source_obj.set("loginUi", active_source.login_ui.unwrap_or_default())?;
                source_obj.set("loginUrl", active_source.login_url.unwrap_or_default())?;
                source_obj.set("variableComment", active_source.variable_comment.unwrap_or_default())?;
            }

            source_obj.set(
                "__runLogin",
                Func::new(|ctx: rquickjs::Ctx<'_>| -> rquickjs::Result<()> {
                    let source = ACTIVE_JS_BOOK_SOURCE
                        .with(|slot| slot.borrow().clone())
                        .unwrap_or_default();
                    let raw = source.login_url.as_deref().unwrap_or("").trim();
                    if raw.is_empty() {
                        return Ok(());
                    }
                    let script = raw
                        .strip_prefix("@js:")
                        .or_else(|| raw.strip_prefix("js:"))
                        .or_else(|| raw.strip_prefix("<js>").and_then(|js| js.strip_suffix("</js>")))
                        .unwrap_or(raw);
                    if url::Url::parse(script.trim()).is_ok_and(|url| {
                        matches!(url.scheme(), "http" | "https")
                    }) {
                        return Err(rquickjs::Exception::throw_type(
                            &ctx, "source.login does not support browser login URLs",
                        ));
                    }
                    let login = format!(
                        "{script}\nif (typeof login === 'function') {{ login.apply(this); }} else {{ throw new Error('Function login not implements!!!'); }}"
                    );
                    with_js_reentrant_ctx(&ctx, || eval_js(&login, "", &source.book_source_url))
                        .map_err(|error| {
                            rquickjs::Exception::throw_type(&ctx, &error.to_string())
                        })?;
                    Ok(())
                }),
            )?;

            let source_key_for_get = source_key_val.clone();
            source_obj.set(
                "get",
                Func::new(move |key: String| -> String {
                    let storage_key = format!("v_{}_{}", source_key_for_get, key);
                    if let Some(active) = current_active_session() {
                        return active
                            .get_variable(&storage_key)
                            .map(|value| match value {
                                serde_json::Value::String(value) => value,
                                serde_json::Value::Null => String::new(),
                                other => other.to_string(),
                            })
                            .unwrap_or_default();
                    }
                    JS_KV
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .get(&storage_key)
                        .cloned()
                        .unwrap_or_default()
                }),
            )?;

            let source_key_for_put = source_key_val.clone();
            source_obj.set(
                "put",
                Func::new(move |key: String, value: String| -> String {
                    let storage_key = format!("v_{}_{}", source_key_for_put, key);
                    if let Some(active) = current_active_session() {
                        active.set_variable_exact(
                            &storage_key,
                            serde_json::Value::String(value.clone()),
                        );
                    } else {
                        JS_KV
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .insert(storage_key, value.clone());
                    }
                    value
                }),
            )?;

            let login_storage_key = format!("userInfo_{source_key_val}");
            let login_storage_key_for_get = login_storage_key.clone();
            source_obj.set("__getLoginInfo", Func::new(move || -> Option<String> {
                if let Some(active) = current_active_session() {
                    return active.get_variable(&login_storage_key_for_get).map(|value| match value {
                        JsonValue::String(value) => value,
                        other => other.to_string(),
                    });
                }
                JS_KV.lock().unwrap_or_else(|error| error.into_inner())
                    .get(&login_storage_key_for_get).cloned()
            }))?;
            source_obj.set("__putLoginInfo", Func::new(move |value: String| -> bool {
                if let Some(active) = current_active_session() {
                    active.set_variable_exact(&login_storage_key, JsonValue::String(value));
                } else {
                    JS_KV.lock().unwrap_or_else(|error| error.into_inner())
                        .insert(login_storage_key.clone(), value);
                }
                true
            }))?;
            let source_key_for_login_info = source_key_val.clone();
            source_obj.set(
                "__removeLoginInfo",
                Func::new(move || {
                    let storage_key = format!("userInfo_{}", source_key_for_login_info);
                    if let Some(active) = current_active_session() {
                        active.remove_variable(&storage_key);
                    } else {
                        JS_KV
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .remove(&storage_key);
                    }
                }),
            )?;

            let source_variable_storage_key = format!("__source_variable:{source_key_val}");
            let source_variable_storage_key_for_get = source_variable_storage_key.clone();
            source_obj.set(
                "getVariable",
                Func::new(move |key: rquickjs::function::Opt<String>| -> String {
                    if let Some(active) = current_active_session() {
                        let value = match key.0.as_deref() {
                            Some(key) => active.get_variable(key),
                            None => active.get_variable(""),
                        };
                        return value
                            .map(|val| match val {
                                serde_json::Value::String(s) => s,
                                serde_json::Value::Null => String::new(),
                                other => other.to_string(),
                            })
                            .unwrap_or_default();
                    }
                    let key = key
                        .0
                        .unwrap_or_else(|| source_variable_storage_key_for_get.clone());
                    JS_KV
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&key)
                        .cloned()
                        .unwrap_or_default()
                }),
            )?;

            let source_variable_storage_key_for_set = source_variable_storage_key.clone();
            source_obj.set(
                "setVariable",
                Func::new(
                    move |first: String, second: rquickjs::function::Opt<String>| {
                        if let Some(active) = current_active_session() {
                            match second.0 {
                                Some(value) => {
                                    let _ = active.set_variable_exact(
                                        &first,
                                        serde_json::Value::String(value),
                                    );
                                }
                                None => {
                                    let _ = active.set_variable(
                                        "",
                                        serde_json::Value::String(first),
                                    );
                                }
                            }
                        } else {
                            let (key, value) = match second.0 {
                                Some(value) => (first, value),
                                None => (source_variable_storage_key_for_set.clone(), first),
                            };
                            JS_KV
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(key, value);
                        }
                    },
                ),
            )?;
            let source_variable_storage_key_for_remove = source_variable_storage_key.clone();
            source_obj.set(
                "__removeVariable",
                Func::new(move || {
                    if let Some(active) = current_active_session() {
                        active.remove_variable("");
                    } else {
                        JS_KV
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&source_variable_storage_key_for_remove);
                    }
                }),
            )?;

            source_obj.set(
                "getLoginHeader",
                Func::new(|| -> Option<String> {
                    current_active_session()
                        .and_then(|active| active.get_login_header())
                        .map(|value| match value {
                            serde_json::Value::String(s) => s,
                            other => other.to_string(),
                        })
                }),
            )?;

            source_obj.set(
                "putLoginHeader",
                Func::new(|ctx: rquickjs::Ctx<'_>, val: String| -> rquickjs::Result<()> {
                    if let Some(active) = current_active_session() {
                        let update = if val.trim_start().starts_with(['{', '[']) {
                            active.put_login_header(serde_json::Value::String(val))
                        } else {
                            active.put_login_header_raw(val)
                        };
                        update.map_err(|message| rquickjs::Exception::throw_type(&ctx, &message))?;
                    }
                    Ok(())
                }),
            )?;

            source_obj.set(
                "removeLoginHeader",
                Func::new(|| {
                    if let Some(active) = current_active_session() {
                        active.remove_login_header();
                    }
                }),
            )?;

            globals.set("source", source_obj)?;
            js_bridge_mark(0, native_mark);
            let native_mark = (*JS_PROFILE_ENABLED).then(Instant::now);

            let cookie_obj = Object::new(ctx.clone())?;
            cookie_obj.set(
                "getCookie",
                Func::new(|url: String| -> String {
                    if let Some(active) = current_active_session() {
                        active.get_cookie(&url).unwrap_or_default()
                    } else {
                        "".to_string()
                    }
                }),
            )?;
            cookie_obj.set(
                "getKey",
                Func::new(|url: String, key: String| -> String {
                    current_active_session()
                        .and_then(|active| active.get_cookie_key(&url, &key))
                        .unwrap_or_default()
                }),
            )?;
            cookie_obj.set(
                "get",
                Func::new(|url: String| -> String {
                    if let Some(active) = current_active_session() {
                        active.get_cookie(&url).unwrap_or_default()
                    } else {
                        "".to_string()
                    }
                }),
            )?;
            cookie_obj.set(
                "setCookie",
                Func::new(|url: String, cookie: String| {
                    if let Some(active) = current_active_session() {
                        active.set_cookie(&url, &cookie);
                    }
                }),
            )?;
            cookie_obj.set(
                "replaceCookie",
                Func::new(|url: String, cookie: String| {
                    if let Some(active) = current_active_session() {
                        let mut merged = parse_cookie_pairs(
                            &active.get_cookie(&url).unwrap_or_default(),
                        );
                        for (key, value) in parse_cookie_pairs(&cookie) {
                            merged.insert(key, value);
                        }
                        if !merged.is_empty() {
                            active.set_cookie(&url, &cookie_pairs_to_string(&merged));
                        }
                    }
                }),
            )?;
            cookie_obj.set(
                "set",
                Func::new(|url: String, cookie: String| {
                    if let Some(active) = current_active_session() {
                        active.set_cookie(&url, &cookie);
                    }
                }),
            )?;
            cookie_obj.set(
                "removeCookie",
                Func::new(|url: String| {
                    if let Some(active) = current_active_session() {
                        active.remove_cookie(&url);
                    }
                }),
            )?;
            cookie_obj.set(
                "remove",
                Func::new(|url: String| {
                    if let Some(active) = current_active_session() {
                        active.remove_cookie(&url);
                    }
                }),
            )?;
            globals.set("cookie", cookie_obj)?;

            let cache_obj = Object::new(ctx.clone())?;
            cache_obj.set(
                "get",
                Func::new(|key: String| -> Option<String> { js_cache_get(&key) }),
            )?;
            cache_obj.set(
                "put",
                Func::new(
                    |key: String, val: String, save_time: rquickjs::function::Opt<i64>| -> bool {
                        js_cache_put(&key, val, save_time.0)
                    },
                ),
            )?;
            cache_obj.set(
                "delete",
                Func::new(|key: String| {
                    let _ = js_cache_delete(&key);
                }),
            )?;
            cache_obj.set(
                "__memoryGet",
                Func::new(|key: String| -> Option<String> {
                    current_active_session()
                        .and_then(|session| session.memory_cache_get(&key))
                        .and_then(|value| serde_json::to_string(&value).ok())
                }),
            )?;
            cache_obj.set(
                "__memoryPut",
                Func::new(|key: String, value: String| {
                    if let Some(session) = current_active_session() {
                        let _ = session.memory_cache_put_serialized(key, &value);
                    }
                }),
            )?;
            cache_obj.set(
                "__memoryDelete",
                Func::new(|key: String| {
                    if let Some(session) = current_active_session() {
                        session.memory_cache_delete(&key);
                    }
                }),
            )?;
            globals.set("cache", cache_obj)?;
            js_bridge_mark(1, native_mark);
            let native_mark = (*JS_PROFILE_ENABLED).then(Instant::now);

            let java_obj = Object::new(ctx.clone())?;
            let file_cache_namespace = ACTIVE_JS_BOOK_SOURCE.with(|cell| {
                cell.borrow().as_ref().map(|source| source.book_source_url.clone())
            }).unwrap_or_else(|| source_key_val.clone());
            java_obj.set(
                "__fileCache",
                Func::new(move |action: String, arguments: String| -> String {
                    let operation = match action.as_str() {
                        "get" => "cache.file.get",
                        "put" => "cache.file.put",
                        "delete" => "cache.file.delete",
                        _ => return serde_json::json!({"ok":false,"error":{
                            "kind":"invalid_argument","message":"invalid cache operation"}}).to_string(),
                    };
                    if file_cache_namespace.is_empty() {
                        return serde_json::json!({"ok":false,"error":{
                            "kind":"unavailable","message":"file cache requires a source context"}}).to_string();
                    }
                    if arguments.len() > 2 * 1024 * 1024 {
                        return serde_json::json!({"ok":false,"error":{
                            "kind":"limit_exceeded","message":"cache request too large"}}).to_string();
                    }
                    let Ok(mut args) = serde_json::from_str::<JsonValue>(&arguments) else {
                        return serde_json::json!({"ok":false,"error":{
                            "kind":"invalid_argument","message":"invalid cache request"}}).to_string();
                    };
                    let Some(object) = args.as_object_mut() else {
                        return serde_json::json!({"ok":false,"error":{
                            "kind":"invalid_argument","message":"invalid cache request"}}).to_string();
                    };
                    object.insert("namespace".into(), JsonValue::String(file_cache_namespace.clone()));
                    crate::host_services::call(operation, &args).to_string()
                }),
            )?;
            let content_for_set = content_state.clone();
            let base_url_for_set = base_url_state.clone();
            java_obj.set(
                "__setContent",
                Func::new(
                    move |content: String, new_base_url: rquickjs::function::Opt<String>| {
                        *content_for_set.lock().unwrap_or_else(|e| e.into_inner()) = content;
                        if let Some(base_url) = new_base_url.0 {
                            *base_url_for_set.lock().unwrap_or_else(|e| e.into_inner()) = base_url;
                        }
                    },
                ),
            )?;
            java_obj.set(
                "__nativeAjax",
                Func::new(|ctx: rquickjs::Ctx<'_>, url: String, timeout_ms: rquickjs::function::Opt<Option<u64>>| -> rquickjs::Result<String> {
                    let timeout = request_call_timeout(&ctx, timeout_ms.0.flatten())?;
                    Ok(with_js_reentrant_ctx(&ctx, || java_analyzed_request_body(&url, timeout)))
                }),
            )?;
            java_obj.set(
                "__cacheFileText",
                Func::new(|ctx: rquickjs::Ctx<'_>, url: String| -> rquickjs::Result<String> {
                    with_js_reentrant_ctx(&ctx, || crate::parser::js_http::java_cache_file_text(&url))
                        .map_err(|error| rquickjs::Exception::throw_message(&ctx, &error))
                }),
            )?;
            java_obj.set(
                "__importScript",
                Func::new(|ctx: rquickjs::Ctx<'_>, path: String| -> Option<String> {
                    with_js_reentrant_ctx(&ctx, || java_import_script(&path))
                }),
            )?;
            java_obj.set(
                "__nativeWebView",
                Func::new(|html: String, url: String, js: String| -> Option<String> {
                    java_web_view(&html, &url, &js)
                }),
            )?;
            java_obj.set(
                "md5Encode",
                Func::new(|input: String| -> String { md5_hex(&input) }),
            )?;
            let md5_to_16 = |input: String| -> String {
                let md5 = md5_hex(&input);
                if md5.len() >= 16 {
                    md5[8..24].to_string()
                } else {
                    md5
                }
            };
            java_obj.set("md5To16", Func::new(md5_to_16))?;
            java_obj.set("md5Encode16", Func::new(md5_to_16))?;
            java_obj.set(
                "toNumChapter",
                Func::new(|input: String| -> String { java_to_num_chapter(&input) }),
            )?;
            java_obj.set(
                "__digestHex",
                Func::new(|data: String, algorithm: String| -> Option<String> {
                    java_digest_bytes(data.as_bytes(), &algorithm).map(hex::encode)
                }),
            )?;
            java_obj.set(
                "__digestBase64",
                Func::new(|data: String, algorithm: String| -> Option<String> {
                    java_digest_bytes(data.as_bytes(), &algorithm)
                        .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
                }),
            )?;
            java_obj.set(
                "__digestBytes",
                Func::new(|data: Vec<u8>, algorithm: String| -> Option<Vec<i8>> {
                    if data.len() > 16384 {
                        return None;
                    }
                    java_digest_bytes(&data, &algorithm)
                        .map(|bytes| bytes.into_iter().map(|byte| byte as i8).collect())
                }),
            )?;
            java_obj.set(
                "__hmacHexString",
                Func::new(
                    |data: String, algorithm: String, key: String| -> Option<String> {
                        java_hmac_string_bytes(&data, &algorithm, &key).map(hex::encode)
                    },
                ),
            )?;
            java_obj.set(
                "__hmacBase64String",
                Func::new(
                    |data: String, algorithm: String, key: String| -> Option<String> {
                        java_hmac_string_bytes(&data, &algorithm, &key)
                            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
                    },
                ),
            )?;
            java_obj.set(
                "__archiveInput",
                Func::new(|url: String| -> String { java_archive_input(&url) }),
            )?;
            java_obj.set(
                "__fontInput",
                Func::new(|ctx: rquickjs::Ctx<'_>, url: String| -> String {
                    with_js_reentrant_ctx(&ctx, || crate::parser::js_http::java_font_input(&url))
                }),
            )?;
            java_obj.set(
                "__hostCall",
                Func::new(|operation: String, arguments: String| -> String {
                    let mark = (*JS_PROFILE_ENABLED).then(Instant::now);
                    let parsed = serde_json::from_str::<JsonValue>(&arguments);
                    js_bridge_mark(3, mark);
                    if *JS_PROFILE_ENABLED {
                        JS_BRIDGE_METRICS.with(|metrics| metrics.borrow_mut().1 += 1);
                    }
                    let Ok(arguments) = parsed else {
                        return serde_json::json!({"ok":false,"error":{"kind":"invalid_argument","message":"invalid host arguments JSON"}}).to_string();
                    };
                    let mark = (*JS_PROFILE_ENABLED).then(Instant::now);
                    let response = crate::host_services::call(&operation, &arguments);
                    js_bridge_mark(4, mark);
                    let mark = (*JS_PROFILE_ENABLED).then(Instant::now);
                    let encoded = response.to_string();
                    js_bridge_mark(5, mark);
                    encoded
                }),
            )?;
            let info_map_source_key = source_key_val.clone();
            java_obj.set(
                "__infoMapSaveNow",
                Func::new(move |payload: String| -> String {
                    if info_map_source_key.is_empty() || payload.len() > MAX_INFO_MAP_BYTES {
                        return serde_json::json!({"ok":false,"error":{"kind":"invalid_argument","message":"invalid infoMap save request"}}).to_string();
                    }
                    let active_source_key = ACTIVE_JS_BOOK_SOURCE.with(|cell| {
                        cell.borrow().as_ref().map(|source| source.book_source_url.clone())
                    });
                    if active_source_key.as_deref().is_some_and(|key| key != info_map_source_key) {
                        return serde_json::json!({"ok":false,"error":{"kind":"permission_denied","message":"infoMap source context mismatch"}}).to_string();
                    }
                    let Ok(value) = serde_json::from_str::<JsonValue>(&payload) else {
                        return serde_json::json!({"ok":false,"error":{"kind":"invalid_argument","message":"invalid infoMap save request"}}).to_string();
                    };
                    let Ok(state) = InfoMapState::from_value(value) else {
                        return serde_json::json!({"ok":false,"error":{"kind":"invalid_argument","message":"invalid infoMap state"}}).to_string();
                    };
                    let arguments = serde_json::json!({"values":state.values,"saveTime":state.save_time});
                    crate::host_services::call("info_map.save_now", &arguments).to_string()
                }),
            )?;
            java_obj.set(
                "__httpUrl",
                Func::new(|spec: String| -> Option<String> { super::http_url::parse(&spec) }),
            )?;
            java_obj.set(
                "__toURL",
                Func::new(
                    |url: String, base_url: rquickjs::function::Opt<String>| -> String {
                        java_to_url_json(&url, base_url.0.as_deref())
                    },
                ),
            )?;
            java_obj.set(
                "getWebViewUA",
                Func::new(|| -> String { webview_user_agent() }),
            )?;
            java_obj.set(
                "timeFormat",
                Func::new(
                    |ctx: rquickjs::Ctx<'_>,
                     timestamp: rquickjs::Coerced<f64>|
                     -> rquickjs::Result<String> {
                        Ok(java_time_format(java_timestamp_long(&ctx, timestamp.0)?))
                    },
                ),
            )?;
            java_obj.set(
                "timeFormatUTC",
                Func::new(
                    |ctx: rquickjs::Ctx<'_>,
                     timestamp: rquickjs::Coerced<f64>,
                     format: String,
                     offset_ms: i64|
                     -> rquickjs::Result<String> {
                        let timestamp = java_timestamp_long(&ctx, timestamp.0)?;
                        Ok(java_time_format_utc(timestamp, &format, offset_ms))
                    },
                ),
            )?;
            java_obj.set(
                "androidId",
                // Android ID 为 64 位十六进制字符串；不要改变 deviceID 的 UUID 兼容行为。
                Func::new(|| -> String {
                    let response = crate::host_services::call("device.android_id", &serde_json::json!({}));
                    let id = response.get("data").and_then(JsonValue::as_str)
                        .filter(|id| response["ok"] == true && !id.is_empty())
                        .unwrap_or(JS_DEVICE_ID.as_str());
                    md5_hex(id)[..16].to_string()
                }),
            )?;
            java_obj.set("deviceID", Func::new(|| -> String {
                // 宿主已持久化标识；不能缓存于进程中，否则子进程/重启会产生新设备。
                let response = crate::host_services::call("device.android_id", &serde_json::json!({}));
                let Some(id) = response.get("data").and_then(JsonValue::as_str)
                    .filter(|id| response["ok"] == true && !id.is_empty()) else {
                    // 无宿主的独立核心调用保留原有兼容行为。
                    return JS_DEVICE_ID.clone();
                };
                // KOReader 默认 UUID 无连字符；保留原位值及 deviceID 的 UUID 外形。
                if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    format!("{}-{}-{}-{}-{}", &id[..8], &id[8..12], &id[12..16], &id[16..20], &id[20..])
                } else {
                    id.to_owned()
                }
            }))?;
            java_obj.set("randomUUID", Func::new(|| -> String { generate_uuid_v4() }))?;
            java_obj.set(
                "__secureRandomNextInt",
                Func::new(|ctx: rquickjs::Ctx<'_>, bound: i32| -> rquickjs::Result<i32> {
                    super::secure_random::next_int(bound)
                        .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error.to_string()))
                }),
            )?;
            java_obj.set(
                "__secureRandomBytes",
                Func::new(|ctx: rquickjs::Ctx<'_>, length: i32| -> rquickjs::Result<String> {
                    let bytes = super::secure_random::bytes(length)
                        .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error.to_string()))?;
                    Ok(serde_json::to_string(&bytes).expect("signed byte array serialization"))
                }),
            )?;
            if active_login_check_request().is_some() {
                java_obj.set(
                    "getUserAgent",
                    Func::new(|| -> String {
                        active_login_check_request()
                            .and_then(|spec| {
                                spec.headers.iter().rev()
                                    .find(|(name, _)| name.eq_ignore_ascii_case("User-Agent"))
                                    .map(|(_, value)| value.clone())
                            })
                            .unwrap_or_else(|| crate::crawler::DEFAULT_USER_AGENT.to_string())
                    }),
                )?;
                java_obj.set(
                    "__loginGetResponseHeaders",
                    Func::new(|ctx: rquickjs::Ctx<'_>| -> rquickjs::Result<String> {
                        let spec = active_login_check_request().ok_or_else(|| {
                            rquickjs::Exception::throw_type(&ctx, "login request scope expired")
                        })?;
                        java_login_response_headers(&spec)
                            .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error))
                    }),
                )?;
                java_obj.set(
                    "__loginGetStrResponse",
                    Func::new(|ctx: rquickjs::Ctx<'_>, use_webview: bool| -> rquickjs::Result<String> {
                        // initUrl may replace this spec after JS setup.
                        let spec = active_login_check_request().ok_or_else(|| {
                            rquickjs::Exception::throw_type(&ctx, "login request scope expired")
                        })?;
                        if use_webview && spec.render_with_rakers {
                            return Err(rquickjs::Exception::throw_type(
                                &ctx, "getStrResponse WebView retry is not supported",
                            ));
                        }
                        Ok(with_js_reentrant_ctx(&ctx, || java_retry_login_request(&spec)))
                    }),
                )?;
                java_obj.set(
                    "__loginInitUrl",
                    Func::new(|ctx: rquickjs::Ctx<'_>| -> rquickjs::Result<String> {
                        let (url, rule_url) = with_js_reentrant_ctx(&ctx, java_init_login_url)
                            .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error))?;
                        Ok(serde_json::json!({"url":url, "ruleUrl":rule_url}).to_string())
                    }),
                )?;
            }
            java_obj.set(
                "__nativeConnect",
                Func::new(
                    |ctx: rquickjs::Ctx<'_>, url: String, headers_json: String, timeout_ms: rquickjs::function::Opt<Option<u64>>| -> rquickjs::Result<String> {
                        let timeout = request_call_timeout(&ctx, timeout_ms.0.flatten())?;
                        Ok(with_js_reentrant_ctx(&ctx, || {
                            java_analyzed_request_response(&url, &headers_json, timeout)
                        }))
                    },
                ),
            )?;
            java_obj.set(
                "__nativeAjaxAllItem",
                Func::new(|ctx: rquickjs::Ctx<'_>, url: String| -> String {
                    with_js_reentrant_ctx(&ctx, || java_analyzed_request_response(&url, "", None))
                }),
            )?;
            java_obj.set(
                "__nativeAjaxTestAllItem",
                Func::new(|ctx: rquickjs::Ctx<'_>, url: String, timeout_ms: u64| -> rquickjs::Result<String> {
                    let timeout = request_call_timeout(&ctx, Some(timeout_ms))?.unwrap();
                    Ok(with_js_reentrant_ctx(&ctx, || java_analyzed_test_request_response(&url, timeout)))
                }),
            )?;
            for (name, method) in [("__nativeGet", "GET"), ("__nativeHead", "HEAD")] {
                java_obj.set(
                    name,
                    Func::new(move |ctx: rquickjs::Ctx<'_>, url: String, headers_json: String, timeout_ms: rquickjs::function::Opt<Option<u64>>| -> rquickjs::Result<String> {
                        let timeout = request_call_timeout(&ctx, timeout_ms.0.flatten())?;
                        Ok(java_request_simple_response(method, &url, None, &headers_json, timeout))
                    }),
                )?;
            }
            java_obj.set(
                "__nativePost",
                Func::new(|ctx: rquickjs::Ctx<'_>, url: String, body: String, headers_json: String, timeout_ms: rquickjs::function::Opt<Option<u64>>| -> rquickjs::Result<String> {
                    let timeout = request_call_timeout(&ctx, timeout_ms.0.flatten())?;
                    Ok(java_request_simple_response("POST", &url, Some(body), &headers_json, timeout))
                }),
            )?;
            java_obj.set(
                "put",
                Func::new(|url: String, body: String| -> String {
                    java_request_simple("PUT", &url, Some(body), "{}").unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "base64Encode",
                Func::new(|input: String| -> String {
                    base64::engine::general_purpose::STANDARD.encode(input)
                }),
            )?;
            java_obj.set(
                "base64Decode",
                Func::new(
                    |input: String, charset: rquickjs::function::Opt<String>| -> String {
                        java_base64_decode(&input, charset.0.as_deref())
                    },
                ),
            )?;
            java_obj.set(
                "base64DecodeBytes",
                Func::new(|input: String| -> String {
                    java_base64_decode_bytes(&input, 0)
                }),
            )?;
            java_obj.set(
                "__base64EncodeBytes",
                Func::new(|bytes_json: String, flags: i32| -> String {
                    java_base64_encode_bytes(&bytes_json, flags)
                }),
            )?;
            java_obj.set(
                "__base64DecodeBytes",
                Func::new(|input: String, flags: i32| -> String {
                    java_base64_decode_bytes(&input, flags)
                }),
            )?;
            java_obj.set(
                "__hmacBytes",
                Func::new(|algorithm: String, key_json: String, data_json: String| -> String {
                    java_hmac_bytes(&algorithm, &key_json, &data_json)
                }),
            )?;
            java_obj.set(
                "__strToBytes",
                Func::new(
                    |input: String, charset: rquickjs::function::Opt<String>| -> String {
                        serde_json::to_string(&java_str_to_bytes(
                            &input,
                            charset.0.as_deref(),
                        ))
                        .unwrap_or_else(|_| "[]".to_string())
                    },
                ),
            )?;
            java_obj.set(
                "__bytesToStr",
                Func::new(|bytes_json: String, charset: String| -> String {
                    let bytes = serde_json::from_str::<Vec<i64>>(&bytes_json)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|byte| byte.rem_euclid(256) as u8)
                        .collect::<Vec<_>>();
                    java_bytes_to_str(&bytes, Some(&charset))
                }),
            )?;
            java_obj.set(
                "__decodeArchiveText",
                Func::new(|bytes_json: String, charset: String| -> Option<String> {
                    let bytes = serde_json::from_str::<Vec<u8>>(&bytes_json).ok()?;
                    decode_archive_text(&bytes, &charset)
                }),
            )?;
            java_obj.set(
                "__hexDecodeBytes",
                Func::new(|input: String| -> String {
                    serde_json::to_string(&hex::decode(input.trim()).unwrap_or_default())
                        .unwrap_or_else(|_| "[]".to_string())
                }),
            )?;
            java_obj.set(
                "hexDecodeToString",
                Func::new(|input: String| -> String {
                    String::from_utf8_lossy(&hex::decode(input.trim()).unwrap_or_default())
                        .into_owned()
                }),
            )?;
            java_obj.set(
                "hexEncodeToString",
                Func::new(|input: String| -> String { hex::encode(input.as_bytes()) }),
            )?;
            java_obj.set(
                "aesDecryptBytes",
                Func::new(|input: String| -> String { java_aes_decrypt_bytes(&input) }),
            )?;
            java_obj.set(
                "__chacha20Poly1305Decrypt",
                Func::new(|ctx: rquickjs::Ctx<'_>, input: String| -> rquickjs::Result<String> {
                    super::chacha20::decrypt_json(&input)
                        .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error.to_string()))
                }),
            )?;
            java_obj.set(
                "__aesGcm",
                Func::new(|ctx: rquickjs::Ctx<'_>, input: String| -> rquickjs::Result<String> {
                    super::aes_gcm::execute_json(&input)
                        .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error.to_string()))
                }),
            )?;
            java_obj.set(
                "__aesDecryptByteArray",
                Func::new(|input: String| -> String {
                    serde_json::to_string(&java_aes_decrypt_byte_array(&input))
                        .unwrap_or_else(|_| "[]".to_string())
                }),
            )?;
            java_obj.set(
                "aesBase64Encode",
                Func::new(
                    |input: String, key: String, algorithm: String, iv: String| -> String {
                        java_aes_base64_encode(&input, &key, &algorithm, &iv)
                    },
                ),
            )?;
            java_obj.set(
                "aesEncode",
                Func::new(
                    |input: String, key: String, algorithm: String, iv: String| -> String {
                        java_aes_encode(&input, &key, &algorithm, &iv)
                    },
                ),
            )?;
            java_obj.set(
                "__signature",
                Func::new(|request: String| -> String {
                    crate::parser::crypto::signature_json(&request)
                }),
            )?;
            java_obj.set(
                "__symmetricCrypto",
                Func::new(
                    |mode: String,
                     transformation: String,
                     key_json: String,
                     iv_json: String,
                     data_json: String|
                     -> Option<String> {
                        java_symmetric_crypto(
                            &mode,
                            &transformation,
                            &key_json,
                            &iv_json,
                            &data_json,
                        )
                    },
                ),
            )?;
            java_obj.set(
                "__decodeSymmetricInput",
                Func::new(|input: String| -> String {
                    serde_json::to_string(&java_decode_symmetric_input(&input))
                        .unwrap_or_else(|_| "[]".to_string())
                }),
            )?;
            java_obj.set(
                "escape",
                Func::new(|input: String| -> String {
                    input
                        .chars()
                        .map(|c| {
                            if c.is_ascii_alphanumeric()
                                || c == '*'
                                || c == '+'
                                || c == '-'
                                || c == '.'
                                || c == '/'
                                || c == '@'
                                || c == '_'
                            {
                                c.to_string()
                            } else if (c as u32) < 256 {
                                format!("%{:02X}", c as u32)
                            } else {
                                format!("%u{:04X}", c as u32)
                            }
                        })
                        .collect()
                }),
            )?;
            java_obj.set(
                "unescape",
                Func::new(|input: String| -> String {
                    // simple unescape implementation
                    let mut res = String::new();
                    let mut chars = input.chars().peekable();
                    while let Some(c) = chars.next() {
                        if c == '%' {
                            if let Some('u') = chars.peek() {
                                chars.next();
                                let mut hex = String::new();
                                for _ in 0..4 {
                                    if let Some(hc) = chars.next() {
                                        hex.push(hc);
                                    }
                                }
                                if let Ok(val) = u32::from_str_radix(&hex, 16) {
                                    if let Some(char_val) = char::from_u32(val) {
                                        res.push(char_val);
                                        continue;
                                    }
                                }
                                res.push_str("%u");
                                res.push_str(&hex);
                            } else {
                                let mut hex = String::new();
                                for _ in 0..2 {
                                    if let Some(hc) = chars.next() {
                                        hex.push(hc);
                                    }
                                }
                                if let Ok(val) = u8::from_str_radix(&hex, 16) {
                                    res.push(val as char);
                                    continue;
                                }
                                res.push('%');
                                res.push_str(&hex);
                            }
                        } else {
                            res.push(c);
                        }
                    }
                    res
                }),
            )?;
            java_obj.set(
                "gzip",
                Func::new(|input: String| -> String {
                    if let Ok(compressed) = crate::parser::compression::gzip(input.as_bytes()) {
                        base64::engine::general_purpose::STANDARD.encode(compressed)
                    } else {
                        String::new()
                    }
                }),
            )?;
            java_obj.set(
                "ungzip",
                Func::new(|input: String| -> String {
                    let input = input.trim();
                    if input.len() > crate::parser::compression::MAX_INPUT.div_ceil(3) * 4 {
                        return String::new();
                    }
                    base64::engine::general_purpose::STANDARD
                        .decode(input)
                        .ok()
                        .and_then(|bytes| crate::parser::compression::gunzip(&bytes).ok())
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "__gzipBytes",
                Func::new(|input: String| -> String {
                    use crate::parser::compression::{self, Error};
                    let result = if input.len() > compression::MAX_OUTPUT * 4 + 2 {
                        Err(Error::LimitExceeded)
                    } else {
                        serde_json::from_str::<Vec<u8>>(&input)
                            .map_err(|_| Error::InvalidInput)
                            .and_then(|bytes| compression::gzip(&bytes))
                    };
                    match result {
                        Ok(bytes) => serde_json::json!({"ok":true,"data":bytes}),
                        Err(error) => serde_json::json!({"ok":false,"error":{
                            "kind":error.kind(),"message":"gzip operation failed"}}),
                    }.to_string()
                }),
            )?;
            for (name, nowrap) in [
                ("__gunzipBytes", None),
                ("__inflateRawBytes", Some(true)),
                ("__inflateZlibBytes", Some(false)),
            ] {
                java_obj.set(
                    name,
                    Func::new(move |input: String| -> String {
                        use crate::parser::compression::{self, Error};
                        let result = if input.len() > compression::MAX_INPUT * 4 + 2 {
                            Err(Error::LimitExceeded)
                        } else {
                            serde_json::from_str::<Vec<u8>>(&input)
                                .map_err(|_| Error::InvalidInput)
                                .and_then(|bytes| match nowrap {
                                    Some(nowrap) => compression::inflate(&bytes, nowrap),
                                    None => compression::gunzip(&bytes),
                                })
                        };
                        match result {
                            Ok(bytes) => serde_json::json!({"ok":true,"data":bytes}),
                            Err(error) => serde_json::json!({"ok":false,"error":{
                                "kind":error.kind(),"message":if nowrap.is_some() {
                                    "inflate operation failed"
                                } else { "gzip operation failed" }}}),
                        }.to_string()
                    }),
                )?;
            }
            java_obj.set(
                "encodeURIComponent",
                Func::new(|input: String| -> String { urlencoding::encode(&input).into_owned() }),
            )?;
            java_obj.set(
                "decodeURIComponent",
                Func::new(|input: String| -> String {
                    urlencoding::decode(&input)
                        .map(|s| s.into_owned())
                        .unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "encodeURI",
                Func::new(
                    |input: String, charset: rquickjs::function::Opt<String>| -> String {
                        java_encode_uri(&input, charset.0.as_deref())
                    },
                ),
            )?;
            java_obj.set(
                "decodeURI",
                Func::new(|input: String| -> String {
                    urlencoding::decode(&input)
                        .map(|s| s.into_owned())
                        .unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "now",
                Func::new(|| -> i64 { chrono::Utc::now().timestamp_millis() }),
            )?;
            java_obj.set(
                "uuid",
                Func::new(|| -> String { generate_uuid_v4() }),
            )?;

            let default_content_for_get_string = content_state.clone();
            let base_url_for_get_string = base_url_state.clone();
            java_obj.set(
                "getString",
                Func::new(
                    move |ctx: rquickjs::Ctx<'_>, rule: Option<String>,
                          content: Option<String>,
                          is_url: Option<bool>,
                          unescape: Option<bool>|
                          -> String {
                        let default_content = if content.is_none() {
                            default_content_for_get_string
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone()
                        } else {
                            String::new()
                        };
                        let base_url = base_url_for_get_string
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        with_js_reentrant_ctx(&ctx, || java_get_string(
                            rule.as_deref(),
                            content.as_deref(),
                            &default_content,
                            &base_url,
                            is_url.unwrap_or(false),
                            unescape.unwrap_or(true),
                        ))
                    },
                ),
            )?;

            let default_content_for_get_string_list = content_state.clone();
            let base_url_for_get_string_list = base_url_state.clone();
            java_obj.set(
                "getStringList",
                Func::new(
                    move |ctx: rquickjs::Ctx<'_>, rule: Option<String>,
                          content: Option<String>,
                          is_url: Option<bool>|
                          -> Vec<String> {
                        let default_content = if content.is_none() {
                            default_content_for_get_string_list
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone()
                        } else {
                            String::new()
                        };
                        let base_url = base_url_for_get_string_list
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        with_js_reentrant_ctx(&ctx, || java_get_string_list(
                            rule.as_deref(),
                            content.as_deref(),
                            &default_content,
                            &base_url,
                            is_url.unwrap_or(false),
                        ))
                    },
                ),
            )?;

            let content_for_elements = content_state.clone();
            let base_url_for_elements = base_url_state.clone();
            java_obj.set(
                "getElements",
                Func::new(
                    move |ctx: rquickjs::Ctx<'_>, rule: String, content: Option<String>, raw_css: Option<bool>, node_identity: Option<bool>| -> String {
                        let default_content = if content.is_none() {
                            content_for_elements
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone()
                        } else {
                            String::new()
                        };
                        let base_url = base_url_for_elements
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        with_js_reentrant_ctx(&ctx, || java_get_elements_json_with_mode(
                            &rule,
                            content.as_deref().unwrap_or(&default_content),
                            &base_url,
                            raw_css.unwrap_or(false),
                            node_identity.unwrap_or(false),
                        ))
                    },
                ),
            )?;
            let content_for_element = content_state.clone();
            let base_url_for_element = base_url_state.clone();
            java_obj.set(
                "getElement",
                Func::new(move |ctx: rquickjs::Ctx<'_>, rule: String, content: Option<String>| -> Option<String> {
                    let default_content = if content.is_none() {
                        content_for_element
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone()
                    } else {
                        String::new()
                    };
                    if let Some(script) = java_js_rule_script(&rule) {
                        let base_url = base_url_for_element.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        let value = with_js_reentrant_ctx(&ctx, || java_element_js_value(
                            script, content.as_deref().unwrap_or(&default_content), &base_url,
                        )).unwrap_or(JsonValue::Null);
                        return serde_json::to_string(&value).ok();
                    }
                    let value: JsonValue = serde_json::from_str(
                        content.as_deref().unwrap_or(&default_content),
                    ).ok()?;
                    let path = if rule.get(..6).is_some_and(|prefix| prefix.eq_ignore_ascii_case("@json:")) {
                        &rule[6..]
                    } else {
                        &rule
                    };
                    let found = jsonpath::jsonpath_object_value(&value, path)?;
                    serde_json::to_string(&found).ok()
                }),
            )?;

            let object_scope_id = bindings
                .and_then(|values| values.get(crate::parser::rule_engine::OBJECT_SCOPE_BINDING))
                .and_then(JsonValue::as_u64);
            java_obj.set(
                "__readerObjectVariablePut",
                Func::new(move |scope: String, key: String, value: String, removed: bool| {
                    if let Some(scope_id) = object_scope_id {
                        crate::parser::rule_engine::record_js_object_variable(
                            scope_id, &scope, &key, (!removed).then_some(value),
                        );
                    }
                }),
            )?;
            let variable_overrides_for_put = variable_overrides.clone();
            java_obj.set(
                "put",
                Func::new(move |key: String, val: rquickjs::Coerced<String>| -> String {
                    let val = val.0;
                    variable_overrides_for_put
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(key.clone(), val.clone());
                    if let Some(active) = current_active_session() {
                        active.set_variable_exact(&key, serde_json::Value::String(val.clone()));
                    } else {
                        JS_KV
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(key, val.clone());
                    }
                    val
                }),
            )?;
            let rule_bindings = bindings.cloned().unwrap_or_default();
            let variable_overrides_for_get = variable_overrides.clone();
            java_obj.set(
                "__nativeVariableGet",
                Func::new(move |key: String| -> String {
                    variable_overrides_for_get
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&key)
                        .cloned()
                        .or_else(|| scoped_java_variable(&rule_bindings, &key))
                        .or_else(|| {
                            current_active_session()
                                .and_then(|session| session.get_variable(&key))
                                .map(|value| json_value_to_string(&value))
                                .filter(|value| !value.is_empty())
                        })
                        .or_else(|| {
                            JS_KV
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .get(&key)
                                .cloned()
                        })
                        .unwrap_or_default()
                }),
            )?;
            java_obj.set("log", Func::new(java_log))?;
            java_obj.set(
                "toast",
                Func::new(|msg: rquickjs::function::Opt<rquickjs::Coerced<String>>| capture_login_message(msg.0)),
            )?;
            java_obj.set(
                "longToast",
                Func::new(|msg: rquickjs::function::Opt<rquickjs::Coerced<String>>| capture_login_message(msg.0)),
            )?;
            java_obj.set(
                "__openUrl",
                Func::new(|ctx: rquickjs::Ctx<'_>, url: String, mime: Option<String>| -> rquickjs::Result<()> {
                    capture_open_url(&url, mime.as_deref())
                        .map_err(|error| rquickjs::Exception::throw_type(&ctx, error))
                }),
            )?;
            java_obj.set("__reLoginView", Func::new(crate::parser::js_state::request_relogin))?;
            java_obj.set("__browserAwait", Func::new(|url: String, title: String| -> String {
                crate::parser::browser_interaction::await_uri(&url, &title).to_string()
            }))?;
            java_obj.set("__browserPreview", Func::new(|url: String, title: String, html: String| -> bool {
                let captured = CLICK_BROWSER.with(|slot| {
                    let mut slot = slot.borrow_mut();
                    if let Some(browser) = slot.as_mut() {
                        // Match the existing preview semantics: latest browser call wins.
                        *browser = Some(serde_json::json!({"url":url,"title":title,"html":html}));
                        true
                    } else { false }
                });
                if captured { return true; }
                if !LOGIN_MESSAGES.with(|slot| slot.borrow().is_some()) { return false; }
                let Some(rendered) = java_web_view(&html, &url, "") else { return false; };
                LOGIN_PREVIEW.with(|slot| *slot.borrow_mut() = Some(serde_json::json!({
                    "title": title, "html": rendered,
                })));
                true
            }))?;
            let base_url_for_html_format = base_url_state.clone();
            java_obj.set(
                "htmlFormat",
                Func::new(move |html: String| -> String {
                    let base_url = base_url_for_html_format
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    crate::parser::html::format_js_html(&html, &base_url)
                }),
            )?;

            java_obj.set("__clickCaptureActive", CLICK_BROWSER.with(|slot| slot.borrow().is_some()))?;
            java_obj.set("__sourceAvailable", source_key.is_some() || ACTIVE_JS_BOOK_SOURCE.with(|slot| slot.borrow().is_some()))?;
            java_obj.set(
                "getCookie",
                Func::new(|url: String, key: rquickjs::function::Opt<Option<String>>| -> String {
                    current_active_session()
                        .and_then(|active| match key.0.flatten() {
                            Some(key) => active.get_cookie_key(&url, &key),
                            None => active.get_cookie(&url),
                        })
                        .unwrap_or_default()
                }),
            )?;
            java_obj.set("__responseDecodeText", Func::new(|bytes: String, charset: Option<String>, parse: bool| -> Option<String> {
                java_response_decode_text(&bytes, charset.as_deref(), parse)
            }))?;
            java_obj.set(
                "__stringMatches",
                Func::new(
                    |ctx: rquickjs::Ctx<'_>, input: String, pattern: String| -> rquickjs::Result<bool> {
                        source_regex::try_full_match(&pattern, &input)
                            .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error.to_string()))
                    },
                ),
            )?;
            java_obj.set(
                "__stringSplit",
                Func::new(
                    |ctx: rquickjs::Ctx<'_>, input: String, pattern: String, limit: i32| -> rquickjs::Result<Vec<String>> {
                        source_regex::split(&input, &pattern, limit)
                            .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error.to_string()))
                    },
                ),
            )?;
            java_obj.set(
                "__stringReplaceAll",
                Func::new(
                    |ctx: rquickjs::Ctx<'_>, input: String, pattern: String, replace: String| -> rquickjs::Result<String> {
                        source_regex::replace_all(&input, &pattern, &replace)
                            .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error.to_string()))
                    },
                ),
            )?;
            java_obj.set(
                "__stringReplaceFirst",
                Func::new(
                    |ctx: rquickjs::Ctx<'_>, input: String, pattern: String, replace: String| -> rquickjs::Result<String> {
                        source_regex::replace_first(&input, &pattern, &replace)
                            .map_err(|error| rquickjs::Exception::throw_type(&ctx, &error.to_string()))
                    },
                ),
            )?;
            globals.set("java", java_obj)?;
            js_bridge_mark(2, native_mark);
            record_js_memory(&mut memory_samples, "native_bindings", &ctx);
            eval_fixed_setup_script(ctx.clone(), BootstrapSlot::Java, bootstrap_dir.as_deref())?;
            record_js_memory(&mut memory_samples, "java", &ctx);

            globals.set(
                "kv_get",
                Func::new(|key: String| -> Option<String> {
                    if let Some(active) = current_active_session() {
                        return active.js_cache_get(&format!("__kv:{key}"));
                    }
                    let map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
                    map.get(&key).cloned()
                }),
            )?;
            globals.set(
                "kv_put",
                Func::new(|key: String, val: String| -> bool {
                    if let Some(active) = current_active_session() {
                        return active.js_cache_put(&format!("__kv:{key}"), val, None);
                    }
                    let mut map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
                    map.insert(key, val);
                    true
                }),
            )?;
            globals.set(
                "regex_replace",
                Func::new(
                    |ctx: rquickjs::Ctx<'_>, input: String, pattern: String, replace: String| -> rquickjs::Result<String> {
                        match source_regex::replace_all(&input, &pattern, &replace) {
                            Ok(value) => Ok(value),
                            Err(source_regex::RegexError::InvalidPattern) => Ok(input),
                            Err(error) => Err(rquickjs::Exception::throw_type(&ctx, &error.to_string())),
                        }
                    },
                ),
            )?;
            globals.set(
                "strip_ws",
                Func::new(|input: String| -> String { strip_whitespace(&input) }),
            )?;

            globals.set("book", Object::new(ctx.clone())?)?;
            globals.set("chapter", Object::new(ctx.clone())?)?;
            globals.set("title", "")?;
            globals.set("nextChapterUrl", "")?;
            globals.set("rssArticle", Object::new(ctx.clone())?)?;

            if let Some(bindings) = bindings {
                for (key, value) in bindings {
                    if key == JAVA_MAP_BINDINGS_KEY
                        || key == crate::parser::rule_engine::OBJECT_SCOPE_BINDING
                    {
                        continue;
                    }
                    let js_value = ctx.json_parse(value.to_string())?;
                    globals.set(key.as_str(), js_value)?;
                }
            }
            eval_fixed_setup_script(ctx.clone(), BootstrapSlot::Source, bootstrap_dir.as_deref())?;

            eval_fixed_setup_script(ctx.clone(), BootstrapSlot::XPath, bootstrap_dir.as_deref())?;

            globals.get::<_, Object<'_>>("java")?.set(
                "__jsoupSiblings",
                Func::new(|source: String, id: String| -> String {
                    jsoup_following_siblings_json(&source, &id)
                }),
            )?;
            globals.get::<_, Object<'_>>("java")?.set(
                "__jsoupRemove",
                Func::new(|source: String, selector: String| -> Option<String> {
                    jsoup_remove_elements(&source, &selector)
                }),
            )?;
            globals.get::<_, Object<'_>>("java")?.set(
                "__jsoupAbsUrl",
                Func::new(|value: String, base: String| -> String {
                    url::Url::parse(&base)
                        .and_then(|base| base.join(&value))
                        .or_else(|_| url::Url::parse(&value))
                        .map(|url| url.to_string())
                        .unwrap_or_default()
                }),
            )?;
            eval_fixed_setup_script(ctx.clone(), BootstrapSlot::Jsoup, bootstrap_dir.as_deref())?;

            record_js_memory(&mut memory_samples, "before_android", &ctx);
            eval_fixed_setup_script(ctx.clone(), BootstrapSlot::Android, bootstrap_dir.as_deref())?;
            // Android installs the reusable Map adapter. Wrap explicitly typed
            // bindings before evaluating source jsLib (which may read result.get()).
            install_explicit_java_map_bindings(&ctx, bindings)?;
            record_js_memory(&mut memory_samples, "android", &ctx);

            // Capture before source scripts can replace the helper; only marked wrappers unwrap.
            let java_string_result: rquickjs::Function<'_> = globals
                .get::<_, Object<'_>>("java")?
                .get("__javaStringResult")?;
            let dom_start = (*JS_PROFILE_ENABLED).then(Instant::now);
            let dom_string_result = dom::install(&ctx)?;
            if let Some(dom_start) = dom_start {
                JS_SETUP_METRICS.with(|totals| totals.borrow_mut()[2] += dom_start.elapsed().as_micros());
            }
            eval_builtin_setup_script(ctx.clone(), BootstrapSlot::Security, bootstrap_dir.as_deref())?;
            eval_builtin_setup_script(ctx.clone(), BootstrapSlot::Math, bootstrap_dir.as_deref())?;
            eval_builtin_setup_script(ctx.clone(), BootstrapSlot::Des, bootstrap_dir.as_deref())?;
            eval_builtin_setup_script(ctx.clone(), BootstrapSlot::Aes, bootstrap_dir.as_deref())?;

            if let Some(state) = active_info_map_state() {
                install_info_map(&ctx, &state)?;
            }
            record_js_memory(&mut memory_samples, "setup_done", &ctx);
            js_profile_mark(&mut profile_mark, &mut profile_stages, 2);
            if !shared_js.trim().is_empty() {
                if *JS_LIB_SPLIT_DIAG {
                    let mut times = [0; 3];
                    let result = eval_js_lib_split(ctx.clone(), &shared_js, &mut times);
                    if *JS_PROFILE_ENABLED {
                        JS_LIB_SPLIT_METRICS.with(|totals| {
                            let mut totals = totals.borrow_mut();
                            for (total, elapsed) in totals.iter_mut().zip(times) {
                                *total += elapsed;
                            }
                        });
                    }
                    result?;
                } else if *JS_LIB_BASELINE_DIAG {
                    eval_script(ctx.clone(), &shared_js)?;
                } else if let Some(session) = current_active_session() {
                    let mut times = [0; 3];
                    let collect = *JS_PROFILE_ENABLED && *JS_LIB_CACHE_DIAG;
                    let result = eval_js_lib_for_operation(
                        ctx.clone(), &shared_js, &session, collect.then_some(&mut times),
                    );
                    if collect {
                        JS_LIB_SPLIT_METRICS.with(|totals| {
                            let mut totals = totals.borrow_mut();
                            for (total, elapsed) in totals.iter_mut().zip(times) {
                                *total += elapsed;
                            }
                        });
                    }
                    result?;
                } else {
                    eval_script(ctx.clone(), &shared_js)?;
                }
            }
            record_js_memory(&mut memory_samples, "jslib", &ctx);
            js_profile_mark(&mut profile_mark, &mut profile_stages, 3);

            eval_script(
                ctx.clone(),
                r#"if (globalThis.result && globalThis.result.__ffiStrResponse === true) {
                    // AnalyzeUrl exposes its request URL as java.url to
                    // loginCheckJs, including StrResponse reconstruction.
                    globalThis.java.url = globalThis.baseUrl;
                    globalThis.result = globalThis.__readerMakeStrResponse(globalThis.result);
                }"#,
            )?;

            // Keep rule lexical declarations local within this evaluation too.
            if let Some((initial, _)) = header_map {
                let java: Object<'_> = globals.get("java")?;
                install_header_map(&ctx, &java, initial)?;
            }
            if let Some((book_url, toc_url)) =
                PRE_UPDATE_TOC_SNAPSHOT.with(|slot| slot.borrow().clone())
            {
                let java: Object<'_> = globals.get("java")?;
                java.set(
                    "refreshTocUrl",
                    Func::new(move |ctx: rquickjs::Ctx<'_>| -> rquickjs::Result<()> {
                        let book: Object<'_> = ctx.globals().get("book")?;
                        let current_url: String = book.get("bookUrl")?;
                        if current_url != book_url {
                            return Err(rquickjs::Exception::throw_type(
                                &ctx,
                                "refreshTocUrl cannot refresh a changed bookUrl in this host",
                            ));
                        }
                        book.set("tocUrl", toc_url.as_str())?;
                        Ok(())
                    }),
                )?;
            }
            js_profile_mark(&mut profile_mark, &mut profile_stages, 4);
            let scoped_script = format!("{{\n{script}\n}}");
            let v = eval_script(ctx.clone(), &scoped_script)?;
            js_profile_mark(&mut profile_mark, &mut profile_stages, 5);
            if let Some((_, updated)) = header_map {
                *updated.borrow_mut() = Some(collect_header_map(&ctx)?);
            }

            let result = if v.is_null() {
                String::new()
            } else if v.is_undefined() {
                if !template_result {
                    if let Ok(res_val) = globals.get::<_, rquickjs::Value<'_>>("result") {
                        if !res_val.is_null() && !res_val.is_undefined() {
                            if let Some(s) = res_val.clone().into_string() {
                                let s: rquickjs::String<'_> = s;
                                s.to_string()
                                    .map(|value| value.to_string())
                                    .unwrap_or_default()
                            } else if let Some(value) = wrapped_string_value(res_val.clone(), &java_string_result, &dom_string_result)? {
                                value
                            } else {
                                match ctx.json_stringify(res_val) {
                                    Ok(Some(json)) => json.to_string().unwrap_or_default(),
                                    _ => String::new(),
                                }
                            }
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            } else if template_result {
                let value: rquickjs::Coerced<std::string::String> =
                    rquickjs::FromJs::from_js(&ctx, v)?;
                value.0
            } else if let Some(s) = v.clone().into_string() {
                let s: rquickjs::String<'_> = s;
                s.to_string()
                    .map(|value| value.to_string())
                    .unwrap_or_default()
            } else if let Some(value) = wrapped_string_value(v.clone(), &java_string_result, &dom_string_result)? {
                value
            } else {
                match ctx.json_stringify(v) {
                    Ok(Some(json)) => json.to_string().unwrap_or_default(),
                    _ => String::new(),
                }
            };

            if active_info_map_state().is_some() {
                let snapshot = eval_script(ctx.clone(), "java.__infoMapSnapshot()")?;
                let snapshot = snapshot
                    .into_string()
                    .ok_or_else(|| anyhow::anyhow!("invalid infoMap snapshot"))?
                    .to_string()?;
                let state = InfoMapState::from_value(serde_json::from_str(&snapshot)?)?;
                update_active_info_map(state);
            }
            Ok(result)
        });
        // Capture partial runs without entering Context::with on the default path.
        if !memory_samples.is_empty() {
            ctx.with(|ctx| record_js_memory(&mut memory_samples, "after_eval", &ctx));
        }
        let drop_mark = (*JS_PROFILE_ENABLED).then(Instant::now);
        drop(ctx);
        if !memory_samples.is_empty() {
            memory_samples.push(("after_drop", runtime.memory_usage()));
        }
        if let Some(mark) = drop_mark {
            profile_cleanup[0] = mark.elapsed().as_micros();
        }
        let gc_mark = (*JS_PROFILE_ENABLED).then(Instant::now);
        runtime.run_gc();
        if !memory_samples.is_empty() {
            memory_samples.push(("after_gc", runtime.memory_usage()));
            report_js_memory(&memory_samples);
        }
        if let Some(mark) = gc_mark {
            profile_cleanup[1] = mark.elapsed().as_micros();
        }
        js_profile_mark(&mut profile_mark, &mut profile_stages, 6);
        if *JS_PROFILE_ENABLED {
            let setup = JS_SETUP_METRICS.with(|totals| *totals.borrow());
            let slots = JS_SETUP_SLOT_METRICS.with(|totals| *totals.borrow());
            let phases = JS_BYTECODE_PHASE_METRICS.with(|totals| *totals.borrow());
            let lib_split = JS_LIB_SPLIT_METRICS.with(|totals| *totals.borrow());
            let lib_cache = JS_LIB_CACHE_STATS.with(|stats| *stats.borrow());
            let bridge = JS_BRIDGE_METRICS.with(|metrics| *metrics.borrow());
            JS_PROFILE_TOTALS.with(|totals| totals.borrow_mut().add(profile_stages, setup, profile_cleanup, slots, phases, lib_split, lib_cache, bridge));
        }
        eval_result
    })
}

fn java_log<'js>(
    ctx: rquickjs::Ctx<'js>,
    msg: rquickjs::function::Opt<Value<'js>>,
) -> rquickjs::Result<Value<'js>> {
    let value = msg.0.unwrap_or_else(|| Value::new_undefined(ctx.clone()));
    let text: rquickjs::Coerced<String> = rquickjs::FromJs::from_js(&ctx, value.clone())?;
    eprintln!("[legado::js] {}", text.0);
    Ok(value)
}

fn scoped_java_variable(bindings: &HashMap<String, JsonValue>, key: &str) -> Option<String> {
    let chapter = bindings.get("chapter");
    let book = bindings.get("book");
    let scoped_value = chapter
        .and_then(|scope| scope.get("variableMap"))
        .and_then(|variables| variables.get(key))
        .or_else(|| {
            book.and_then(|scope| scope.get("variableMap"))
                .and_then(|variables| variables.get(key))
        })
        .or_else(|| chapter.and_then(|scope| scope.get(key)))
        .or_else(|| book.and_then(|scope| scope.get(key)))
        .or_else(|| {
            (key == "bookName")
                .then(|| book.and_then(|scope| scope.get("name")))
                .flatten()
        })
        .or_else(|| bindings.get(key));
    scoped_value.map(json_value_to_string)
}

fn wrapped_string_value<'js>(
    value: Value<'js>,
    java: &rquickjs::Function<'js>,
    dom: &Option<rquickjs::Function<'js>>,
) -> rquickjs::Result<Option<String>> {
    if let Some(extract) = dom {
        let unwrapped: Value<'js> = extract.call((value.clone(),))?;
        if let Some(string) = unwrapped.into_string() {
            return string.to_string().map(Some);
        }
    }
    let unwrapped: Value<'js> = java.call((value,))?;
    unwrapped
        .into_string()
        .map(|string| string.to_string())
        .transpose()
}

fn snapshot_object_properties<'js>(
    object: &Object<'js>,
) -> anyhow::Result<HashMap<String, Value<'js>>> {
    let mut snapshot = HashMap::new();
    for key in object.keys::<String>() {
        let key = key?;
        snapshot.insert(key.clone(), object.get::<_, Value<'js>>(key.as_str())?);
    }
    Ok(snapshot)
}

fn restore_object_properties<'js>(
    object: &Object<'js>,
    snapshot: HashMap<String, Value<'js>>,
) -> anyhow::Result<()> {
    let current_keys = object
        .keys::<String>()
        .collect::<rquickjs::Result<Vec<_>>>()?;
    for key in current_keys {
        if !snapshot.contains_key(&key) {
            object.remove(key.as_str())?;
        }
    }
    for (key, value) in snapshot {
        object.set(key.as_str(), value)?;
    }
    Ok(())
}

fn eval_js_reentrant<'js>(
    ctx: rquickjs::Ctx<'js>,
    script: &str,
    input: Option<&str>,
    base_url: Option<&str>,
    key: Option<&str>,
    page: Option<i32>,
    _source_key: Option<&str>,
    bindings: Option<&HashMap<String, JsonValue>>,
    template_result: bool,
) -> anyhow::Result<String> {
    let globals = ctx.globals();
    let globals_snapshot = snapshot_object_properties(&globals)?;
    let java: Object<'js> = globals.get("java")?;
    let java_snapshot = snapshot_object_properties(&java)?;
    let mut saved = Vec::<(String, Option<Value<'js>>)>::new();

    let mut save_global = |name: &str| -> anyhow::Result<()> {
        if saved.iter().any(|(saved_name, _)| saved_name == name) {
            return Ok(());
        }
        let value = if globals.contains_key(name)? {
            Some(globals.get::<_, Value<'js>>(name)?)
        } else {
            None
        };
        saved.push((name.to_string(), value));
        Ok(())
    };

    for name in [
        "input", "result", "src", "base_url", "baseUrl", "url", "key", "page",
    ] {
        save_global(name)?;
    }
    if let Some(bindings) = bindings {
        for name in bindings.keys() {
            if name != JAVA_MAP_BINDINGS_KEY {
                save_global(name)?;
            }
        }
    }

    let result = (|| -> anyhow::Result<String> {
        let input_value = input.unwrap_or("");
        let base_url_value = base_url.unwrap_or("");
        globals.set("input", input_value)?;
        globals.set("result", input_value)?;
        globals.set("src", input_value)?;
        globals.set("base_url", base_url_value)?;
        globals.set("baseUrl", base_url_value)?;
        globals.set("url", base_url_value)?;
        if let Some(key) = key {
            globals.set("key", key)?;
        }
        if let Some(page) = page {
            globals.set("page", page)?;
        }
        if let Some(bindings) = bindings {
            for (name, value) in bindings {
                if name == JAVA_MAP_BINDINGS_KEY {
                    continue;
                }
                globals.set(name.as_str(), ctx.json_parse(value.to_string())?)?;
            }
        }
        install_explicit_java_map_bindings(&ctx, bindings)?;

        let dom_string_result = dom::install(&ctx)?;
        let dom_string = |value: Value<'js>| -> rquickjs::Result<Option<String>> {
            match &dom_string_result {
                Some(extract) => {
                    let value: Value<'js> = extract.call((value,))?;
                    value
                        .into_string()
                        .map(|string| string.to_string())
                        .transpose()
                }
                None => Ok(None),
            }
        };

        // Direct eval inside a temporary function keeps nested AnalyzeUrl
        // var/function declarations local while preserving eval's completion value.
        // Explicit globalThis/java mutations are restored by the snapshots below.
        let source = serde_json::to_string(script)?;
        let scoped_script = format!("(function() {{ return eval({source}); }})()");
        let value = eval_script(ctx.clone(), &scoped_script)?;
        if value.is_null() {
            return Ok(String::new());
        }
        if value.is_undefined() {
            if template_result {
                return Ok(String::new());
            }
            let result_value = globals.get::<_, Value<'js>>("result")?;
            if result_value.is_null() || result_value.is_undefined() {
                return Ok(String::new());
            }
            if let Some(string) = result_value.clone().into_string() {
                return Ok(string.to_string().unwrap_or_default());
            }
            if let Some(string) = dom_string(result_value.clone())? {
                return Ok(string);
            }
            return Ok(ctx
                .json_stringify(result_value)?
                .and_then(|json| json.to_string().ok())
                .unwrap_or_default());
        }
        if template_result {
            let value: rquickjs::Coerced<String> = rquickjs::FromJs::from_js(&ctx, value)?;
            return Ok(value.0);
        }
        if let Some(string) = value.clone().into_string() {
            return Ok(string.to_string().unwrap_or_default());
        }
        if let Some(string) = dom_string(value.clone())? {
            return Ok(string);
        }
        Ok(ctx
            .json_stringify(value)?
            .and_then(|json| json.to_string().ok())
            .unwrap_or_default())
    })();

    for (name, value) in saved.into_iter().rev() {
        match value {
            Some(value) => {
                let _ = globals.set(name.as_str(), value);
            }
            None => {
                let _ = globals.remove(name.as_str());
            }
        }
    }

    let java_restore = restore_object_properties(&java, java_snapshot);
    let globals_restore = restore_object_properties(&globals, globals_snapshot);
    match result {
        Err(error) => Err(error),
        Ok(value) => {
            java_restore?;
            globals_restore?;
            Ok(value)
        }
    }
}

fn finalize_java_get_string_url(value: String, base_url: &str, is_url: bool) -> String {
    if !is_url {
        value
    } else if value.trim().is_empty() {
        base_url.to_string()
    } else {
        rule_engine::resolve_url(base_url, &value)
    }
}

pub(crate) fn java_get_string(
    rule: Option<&str>,
    content: Option<&str>,
    default_content: &str,
    base_url: &str,
    is_url: bool,
    unescape: bool,
) -> String {
    let Some(rule) = rule.map(str::trim).filter(|s| !s.is_empty()) else {
        return String::new();
    };

    let js_rule = java_js_rule_script(rule).is_some();
    let target_content = content.unwrap_or(default_content);
    let target_content = if js_rule {
        target_content
    } else {
        target_content.trim()
    };
    if target_content.is_empty() && !js_rule {
        return finalize_java_get_string_url(String::new(), base_url, is_url);
    }

    // JS rules own their logical operators; combine only extraction rules.
    let delimiters: &[&str] = if js_rule { &[] } else { &["||", "&&"] };
    let split = rule_analyzer::split_top_level(rule, delimiters);
    if let Some(delim) = split.delimiter.as_deref() {
        if delim == "||" {
            for part in split.parts {
                let res = java_get_string(
                    Some(&part),
                    content,
                    default_content,
                    base_url,
                    false,
                    unescape,
                );
                if !res.is_empty() {
                    return finalize_java_get_string_url(res, base_url, is_url);
                }
            }
            return finalize_java_get_string_url(String::new(), base_url, is_url);
        } else if delim == "&&" {
            let mut results = Vec::new();
            for part in split.parts {
                let res = java_get_string(
                    Some(&part),
                    content,
                    default_content,
                    base_url,
                    false,
                    unescape,
                );
                if !res.is_empty() {
                    results.push(res);
                }
            }
            return finalize_java_get_string_url(results.join("\n"), base_url, is_url);
        }
    }

    // 分离 ## 替换正则 (规范 6.7)
    let (main_rule, regex_part) = rule_engine::split_legado_regex(rule);
    let main_rule = main_rule.trim();

    let mut res = if main_rule.is_empty() {
        target_content.to_string()
    } else if main_rule.starts_with("<js>")
        || main_rule.starts_with("@js:")
        || main_rule.starts_with("js:")
    {
        let script = rule_engine::strip_js_rule(main_rule);
        eval_js(script, target_content, base_url).unwrap_or_default()
    } else if let Some(pure) = html::xpath_rule(main_rule) {
        html::select_xpath_from_context(target_content, pure)
            .unwrap_or_else(|| html::select_xpath(target_content, pure))
            .join("\n")
    } else if main_rule.starts_with("@json:")
        || main_rule.starts_with("@Json:")
        || main_rule.starts_with("@JSON:")
        || main_rule.starts_with("$.")
        || main_rule.starts_with("$[")
        || (target_content.starts_with('{') || target_content.starts_with('['))
    {
        // JSON 模式
        let pure = if let Some(stripped) = main_rule
            .strip_prefix("@json:")
            .or_else(|| main_rule.strip_prefix("@Json:"))
            .or_else(|| main_rule.strip_prefix("@JSON:"))
        {
            stripped.trim()
        } else {
            main_rule
        };

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(target_content) {
            if pure.is_empty() {
                jsonpath::value_to_string(&v).unwrap_or_default()
            } else if pure.starts_with('$') {
                jsonpath::jsonpath_first_string(&v, pure).unwrap_or_default()
            } else if let Some(val) = v.get(pure) {
                jsonpath::value_to_string(val).unwrap_or_default()
            } else {
                jsonpath::jsonpath_first_string(&v, &format!("$.{}", pure)).unwrap_or_default()
            }
        } else {
            String::new()
        }
    } else if main_rule.starts_with("@regex:") || main_rule.starts_with(':') {
        // Regex 模式
        let pure = if let Some(stripped) = main_rule.strip_prefix("@regex:") {
            stripped.trim()
        } else {
            &main_rule[1..]
        };
        source_regex::captures_first(pure, target_content)
            .and_then(|captures| {
                captures
                    .get(1)
                    .and_then(Clone::clone)
                    .or_else(|| captures.first().and_then(Clone::clone))
            })
            .unwrap_or_default()
    } else {
        // 默认 CSS / HTML 模式
        let pure = if let Some(stripped) = main_rule
            .strip_prefix("@@")
            .or_else(|| main_rule.strip_prefix("@css:"))
            .or_else(|| main_rule.strip_prefix("@CSS:"))
        {
            stripped.trim()
        } else {
            main_rule
        };
        let doc = html::parse_document(target_content);
        html::select_all_text(&doc, pure)
            .or_else(|| html::select_text(&doc, pure))
            .unwrap_or_default()
    };

    if let Some(regex) = regex_part {
        res = rule_engine::apply_legado_regex(&res, regex);
    }

    if unescape && res.contains('&') {
        res = html::html_unescape(&res);
    }

    finalize_java_get_string_url(res, base_url, is_url)
}

pub(crate) fn java_get_string_list(
    rule: Option<&str>,
    content: Option<&str>,
    default_content: &str,
    base_url: &str,
    is_url: bool,
) -> Vec<String> {
    let list = java_get_string_list_inner(rule, content, default_content, base_url);
    if !is_url {
        return list;
    }
    // AnalyzeRule normalizes and deduplicates only the completed URL list.
    let mut urls = Vec::new();
    for item in list {
        let url = rule_engine::resolve_url(base_url, &item);
        if !url.is_empty() && !urls.contains(&url) {
            urls.push(url);
        }
    }
    urls
}

fn java_get_string_list_inner(
    rule: Option<&str>,
    content: Option<&str>,
    default_content: &str,
    base_url: &str,
) -> Vec<String> {
    let Some(rule) = rule.map(str::trim).filter(|s| !s.is_empty()) else {
        return Vec::new();
    };

    let js_rule = java_js_rule_script(rule).is_some();
    let target_content = content.unwrap_or(default_content);
    let target_content = if js_rule {
        target_content
    } else {
        target_content.trim()
    };
    if target_content.is_empty() && !js_rule {
        return Vec::new();
    }

    // JS rules own their logical operators; combine only extraction rules.
    let delimiters: &[&str] = if js_rule { &[] } else { &["||", "&&", "%%"] };
    let split = rule_analyzer::split_top_level(rule, delimiters);
    if let Some(delim) = split.delimiter.as_deref() {
        if delim == "||" {
            for part in split.parts {
                let res =
                    java_get_string_list_inner(Some(&part), content, default_content, base_url);
                if !res.is_empty() {
                    return res;
                }
            }
            return Vec::new();
        } else if delim == "&&" {
            let mut results = Vec::new();
            for part in split.parts {
                results.extend(java_get_string_list_inner(
                    Some(&part),
                    content,
                    default_content,
                    base_url,
                ));
            }
            return results;
        } else if delim == "%%" {
            let groups = split
                .parts
                .iter()
                .map(|part| {
                    java_get_string_list_inner(Some(part), content, default_content, base_url)
                })
                .collect();
            return rule_analyzer::interleave_result_groups(groups);
        }
    }

    // 分离 ## 替换正则 (规范 6.7)
    let (main_rule, regex_part) = rule_engine::split_legado_regex(rule);
    let main_rule = main_rule.trim();

    let mut list = if main_rule.is_empty() {
        vec![target_content.to_string()]
    } else if main_rule.starts_with("<js>")
        || main_rule.starts_with("@js:")
        || main_rule.starts_with("js:")
    {
        let script = rule_engine::strip_js_rule(main_rule);
        // Tag the result before eval_js stringifies it: a real JS array is
        // a list, while a string containing JSON remains ordinary text.
        let encoded = serde_json::to_string(script).unwrap();
        let tagged = format!(
            r#"(function(values) {{
            const raw = values[0] === undefined ? values[1] : values[0];
            const value = java.__javaStringResult(raw) ?? raw;
            return JSON.stringify(Array.isArray(value)
                ? {{items: value.map(item => String(item))}}
                : value == null ? {{items: []}}
                : {{text: typeof value === 'string' ? value : JSON.stringify(value)}});
        }})((function() {{ return [eval({encoded}), globalThis.result]; }})())"#
        );
        eval_js(&tagged, target_content, base_url)
            .ok()
            .and_then(|result| serde_json::from_str::<JsonValue>(&result).ok())
            .map(|result| {
                if let Some(items) = result.get("items").and_then(JsonValue::as_array) {
                    items
                        .iter()
                        .filter_map(JsonValue::as_str)
                        .map(str::to_owned)
                        .collect()
                } else {
                    result
                        .get("text")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .split('\n')
                        .map(str::to_owned)
                        .collect()
                }
            })
            .unwrap_or_default()
    } else if let Some(pure) = html::xpath_rule(main_rule) {
        html::select_xpath_from_context(target_content, pure)
            .unwrap_or_else(|| html::select_xpath(target_content, pure))
    } else if main_rule.starts_with("@json:")
        || main_rule.starts_with("@Json:")
        || main_rule.starts_with("@JSON:")
        || main_rule.starts_with("$.")
        || main_rule.starts_with("$[")
        || (target_content.starts_with('{') || target_content.starts_with('['))
    {
        let pure = if let Some(stripped) = main_rule
            .strip_prefix("@json:")
            .or_else(|| main_rule.strip_prefix("@Json:"))
            .or_else(|| main_rule.strip_prefix("@JSON:"))
        {
            stripped.trim()
        } else {
            main_rule
        };

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(target_content) {
            if pure.starts_with('$') {
                jsonpath::jsonpath_query(&v, pure)
                    .iter()
                    .filter_map(jsonpath::value_to_string)
                    .collect()
            } else if let Some(val) = v.get(pure) {
                match val {
                    serde_json::Value::Array(arr) => {
                        arr.iter().filter_map(jsonpath::value_to_string).collect()
                    }
                    other => jsonpath::value_to_string(other).into_iter().collect(),
                }
            } else {
                jsonpath::jsonpath_query(&v, &format!("$.{}", pure))
                    .iter()
                    .filter_map(jsonpath::value_to_string)
                    .collect()
            }
        } else {
            Vec::new()
        }
    } else if main_rule.starts_with("@regex:") || main_rule.starts_with(':') {
        let pure = if let Some(stripped) = main_rule.strip_prefix("@regex:") {
            stripped.trim()
        } else {
            &main_rule[1..]
        };
        source_regex::captures_all(pure, target_content)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|captures| {
                captures
                    .get(1)
                    .and_then(Clone::clone)
                    .or_else(|| captures.first().and_then(Clone::clone))
            })
            .collect()
    } else {
        let pure = if let Some(stripped) = main_rule
            .strip_prefix("@@")
            .or_else(|| main_rule.strip_prefix("@css:"))
            .or_else(|| main_rule.strip_prefix("@CSS:"))
        {
            stripped.trim()
        } else {
            main_rule
        };
        let doc = html::parse_document(target_content);
        html::select_text_list(&doc, pure)
    };

    if let Some(regex) = regex_part {
        list = list
            .into_iter()
            .map(|item| rule_engine::apply_legado_regex(&item, regex))
            .collect();
    }

    list
}

fn jsoup_remove_elements(source: &str, selector: &str) -> Option<String> {
    if !html::css_rule_is_valid(selector) {
        return None;
    }
    let mut document = html::parse_document(source);
    let ids = html::select_css_list(&document, selector)
        .iter()
        .map(|element| element.id())
        .collect::<Vec<_>>();
    for id in ids {
        if let Some(mut node) = document.tree.get_mut(id) {
            node.detach();
        }
    }
    Some(document.html())
}

fn java_js_rule_script(rule: &str) -> Option<&str> {
    let rule = rule.trim();
    (rule.starts_with("@js:") || rule.starts_with("js:") || rule.starts_with("<js>"))
        .then(|| rule_engine::strip_js_rule(rule))
}

fn java_element_js_value(script: &str, content: &str, base_url: &str) -> Option<JsonValue> {
    // Keep the JS type before the generic evaluator converts it to text.
    // Only undefined completion falls back to result; null and empty string do not.
    let encoded = serde_json::to_string(script).ok()?;
    let tagged = format!(
        r#"(function(values) {{
        return JSON.stringify({{value: values[0] === undefined ? values[1] : values[0]}});
    }})((function() {{ return [eval({encoded}), globalThis.result]; }})())"#
    );
    let result = eval_js(&tagged, content, base_url).ok()?;
    serde_json::from_str::<JsonValue>(&result)
        .ok()?
        .get("value")
        .cloned()
}

fn java_get_elements_json_with_mode(
    rule: &str,
    content: &str,
    base_url: &str,
    raw_css: bool,
    node_identity: bool,
) -> String {
    let rule = rule.trim();
    if !raw_css {
        if let Some(script) = java_js_rule_script(rule) {
            let values = match java_element_js_value(script, content, base_url) {
                Some(JsonValue::Array(items)) => items
                    .into_iter()
                    .filter(|item| !item.is_null())
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            };
            return serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string());
        }
    }
    let content = content.trim();
    if rule.is_empty() || content.is_empty() {
        return "[]".to_string();
    }

    let lower_rule = rule.to_ascii_lowercase();
    let explicit_css = rule.starts_with("@@") || lower_rule.starts_with("@css:");
    let explicit_other_mode = html::xpath_rule(rule).is_some()
        || lower_rule.starts_with("@regex:")
        || lower_rule.starts_with("@js:")
        || lower_rule.starts_with("js:")
        || rule.starts_with(':');
    let json_content = serde_json::from_str::<JsonValue>(content).ok();
    let json_rule = rule.starts_with('$') || lower_rule.starts_with("@json:");
    if !raw_css && !explicit_css && !explicit_other_mode && (json_rule || json_content.is_some()) {
        let Some(value) = json_content else {
            return "[]".to_string();
        };
        let pure = if lower_rule.starts_with("@json:") {
            &rule[6..]
        } else {
            rule
        }
        .trim();
        let values = if pure.starts_with('$') {
            jsonpath::jsonpath_query(&value, pure)
        } else if let Some(found) = value.get(pure) {
            match found {
                JsonValue::Array(items) => items.clone(),
                other => vec![other.clone()],
            }
        } else {
            jsonpath::jsonpath_query(&value, &format!("$.{pure}"))
        };
        return serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string());
    }

    if !raw_css {
        if let Some(pure) = html::xpath_rule(rule) {
            return html::select_xpath_elements_from_context(content, pure)
                .unwrap_or_else(|| html::select_xpath_elements_json(content, pure));
        }
    }

    if !raw_css && (rule.starts_with("@regex:") || rule.starts_with(':')) {
        let values = java_get_string_list(Some(rule), Some(content), "", base_url, false)
            .into_iter()
            .map(JsonValue::String)
            .collect::<Vec<_>>();
        return serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string());
    }

    let selector = if raw_css {
        rule
    } else if let Some(selector) = rule.strip_prefix("@@") {
        selector
    } else if lower_rule.starts_with("@css:") {
        &rule[5..]
    } else {
        rule
    }
    .trim();
    let document = html::parse_document(content);
    let elements = if raw_css {
        html::select_css_list(&document, selector)
    } else {
        html::select_list(&document, selector)
    };
    let values = elements
        .into_iter()
        .map(|element| jsoup_html_element_json(element, node_identity))
        .collect::<Vec<_>>();
    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

fn jsoup_html_element_json(element: scraper::ElementRef<'_>, with_identity: bool) -> JsonValue {
    let attr_list = element
        .value()
        .attrs()
        .map(|(name, value)| (name.to_string(), JsonValue::String(value.to_string())))
        .collect::<Vec<_>>();
    let attrs = attr_list.iter().cloned().collect::<serde_json::Map<_, _>>();
    let mut item = serde_json::json!({
        "__readerHtmlElement": true,
        "attrs": attrs,
        "attrList": attr_list,
        "html": element.inner_html(),
        "outerHtml": element.html(),
        "text": element.text().collect::<Vec<_>>().join(" ").trim(),
    });
    if with_identity {
        item["__readerHtmlNodeId"] = format!("{:?}", element.id()).into();
    }
    item
}

// Used only by Jsoup.nextElementSibling(); return the remainder in one parse.
fn jsoup_following_siblings_json(source: &str, id: &str) -> String {
    let document = html::parse_document(source.trim());
    let mut next = document.tree.nodes()
        .find(|node| format!("{:?}", node.id()) == id)
        .and_then(|node| node.next_sibling());
    let mut siblings = Vec::new();
    while let Some(node) = next {
        next = node.next_sibling();
        if let Some(element) = scraper::ElementRef::wrap(node) {
            siblings.push(jsoup_html_element_json(element, true));
            if siblings.len() >= 4096 { break; }
        }
    }
    serde_json::to_string(&siblings).unwrap_or_else(|_| "[]".into())
}

fn java_aes_decrypt_byte_array(input: &str) -> Vec<u8> {
    let Ok(value) = serde_json::from_str::<JsonValue>(input) else {
        return Vec::new();
    };
    let bytes = |key: &str| -> Option<Vec<u8>> {
        value
            .get(key)?
            .as_array()?
            .iter()
            .map(|byte| u8::try_from(byte.as_u64()?).ok())
            .collect()
    };
    if value.get("mode").and_then(JsonValue::as_i64) != Some(2)
        || !matches!(
            value
                .get("algorithm")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_ascii_uppercase()
                .as_str(),
            "AES/CBC/PKCS5PADDING" | "AES/CBC/PKCS7PADDING"
        )
    {
        return Vec::new();
    }
    let (Some(key), Some(iv), Some(mut encrypted)) = (bytes("key"), bytes("iv"), bytes("data"))
    else {
        return Vec::new();
    };
    let Ok(cipher) = Aes128CbcDecryptor::new_from_slices(&key, &iv) else {
        return Vec::new();
    };
    cipher
        .decrypt_padded_mut::<Pkcs7>(&mut encrypted)
        .map(|plaintext| plaintext.to_vec())
        .unwrap_or_default()
}

fn java_aes_decrypt_bytes(input: &str) -> String {
    String::from_utf8(java_aes_decrypt_byte_array(input)).unwrap_or_default()
}

fn java_aes_base64_encode(input: &str, key: &str, algorithm: &str, iv: &str) -> String {
    let algorithm = algorithm.to_ascii_uppercase();
    if algorithm != "AES/CBC/PKCS5PADDING" && algorithm != "AES/CBC/PKCS7PADDING" {
        return String::new();
    }
    let Ok(cipher) = Aes128CbcEncryptor::new_from_slices(key.as_bytes(), iv.as_bytes()) else {
        return String::new();
    };
    let mut buf = vec![0u8; input.len() + 16];
    buf[..input.len()].copy_from_slice(input.as_bytes());
    if let Ok(encrypted) = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, input.len()) {
        base64::engine::general_purpose::STANDARD.encode(encrypted)
    } else {
        String::new()
    }
}

fn java_aes_encode(input: &str, key: &str, algorithm: &str, iv: &str) -> String {
    let algorithm = algorithm.to_ascii_uppercase();
    if algorithm != "AES/CBC/PKCS5PADDING" && algorithm != "AES/CBC/PKCS7PADDING" {
        return String::new();
    }
    let Ok(cipher) = Aes128CbcEncryptor::new_from_slices(key.as_bytes(), iv.as_bytes()) else {
        return String::new();
    };
    let mut buf = vec![0u8; input.len() + 16];
    buf[..input.len()].copy_from_slice(input.as_bytes());
    if let Ok(encrypted) = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, input.len()) {
        hex::encode(encrypted)
    } else {
        String::new()
    }
}

fn java_decode_symmetric_input(input: &str) -> Vec<u8> {
    let input = input.trim();
    if !input.is_empty()
        && input.len().is_multiple_of(2)
        && input.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        if let Ok(bytes) = hex::decode(input) {
            return bytes;
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input))
        .unwrap_or_default()
}

fn java_symmetric_crypto(
    mode: &str,
    transformation: &str,
    key_json: &str,
    iv_json: &str,
    data_json: &str,
) -> Option<String> {
    let key: Vec<u8> = serde_json::from_str(key_json).ok()?;
    let iv: Vec<u8> = serde_json::from_str(iv_json).ok()?;
    let data: Vec<u8> = serde_json::from_str(data_json).ok()?;
    let output = crate::parser::crypto::symmetric(mode, transformation, &key, &iv, &data)?;
    serde_json::to_string(&output).ok()
}

// Legado rules commonly assign undeclared globals, so evaluate them as sloppy
// global scripts rather than modules/strict scripts.
// Diagnostic alternative to eval_script, never used without explicit opt-in.
// Compile only once per invocation, then execute exactly once in the same
// fresh Context. This separates compilation from top-level side effects.
fn eval_js_lib_split<'js>(
    ctx: rquickjs::Ctx<'js>,
    script: &str,
    timings: &mut [u128; 3],
) -> anyhow::Result<Value<'js>> {
    let source = std::ffi::CString::new(script)?;
    let raw_ctx = ctx.as_raw().as_ptr();
    let compile_start = Instant::now();
    // SAFETY: script and filename remain valid for the entire call. Match
    // eval_script's non-strict global mode and eval_script filename.
    let compiled = unsafe {
        rquickjs::qjs::JS_Eval(
            raw_ctx,
            source.as_ptr(),
            script.len() as _,
            c"eval_script".as_ptr(),
            (rquickjs::qjs::JS_EVAL_TYPE_GLOBAL | rquickjs::qjs::JS_EVAL_FLAG_COMPILE_ONLY) as _,
        )
    };
    timings[0] = compile_start.elapsed().as_micros();
    if unsafe { rquickjs::qjs::JS_IsException(compiled) } {
        return Err(anyhow::anyhow!("JS Exception: {:?}", ctx.catch()));
    }
    // SAFETY: JS_EvalFunction consumes the owned bytecode value even on error.
    let exec_start = Instant::now();
    let result = unsafe { rquickjs::qjs::JS_EvalFunction(raw_ctx, compiled) };
    timings[2] = exec_start.elapsed().as_micros();
    if unsafe { rquickjs::qjs::JS_IsException(result) } {
        Err(anyhow::anyhow!("JS Exception: {:?}", ctx.catch()))
    } else {
        Ok(unsafe { Value::from_raw(ctx, result) })
    }
}

// Production: only reuse serialized bytecode within one active reader_execute
// operation. Never keep the source or bytecode after the session is dropped.
fn eval_js_lib_for_operation<'js>(
    ctx: rquickjs::Ctx<'js>,
    script: &str,
    session: &crate::runtime::session::ActiveSession,
    mut times: Option<&mut [u128; 3]>,
) -> anyhow::Result<Value<'js>> {
    if !crate::runtime::session::ActiveSession::allows_js_lib_bytecode(script) {
        return eval_script(ctx, script);
    }
    let bytes = if let Some(bytes) = session.js_lib_bytecode_get(script) {
        if times.is_some() {
            JS_LIB_CACHE_STATS.with(|stats| stats.borrow_mut().0 += 1);
        }
        bytes
    } else {
        // Compile once for this operation. Errors propagate without retry.
        let start = times.as_ref().map(|_| Instant::now());
        let compiled = js_bytecode::compile(&ctx, script);
        if let Some(start) = start {
            times.as_deref_mut().unwrap()[0] = start.elapsed().as_micros();
        }
        let bytes = compiled?;
        session.js_lib_bytecode_put(script, bytes.clone());
        bytes
    };
    if times.is_some() {
        JS_LIB_CACHE_STATS.with(|stats| {
            let mut stats = stats.borrow_mut();
            stats.1 = stats.1.max(bytes.len());
        });
    }
    let mut phases = js_bytecode::BytecodeTimings::default();
    let result = js_bytecode::execute(ctx, &bytes, times.as_ref().map(|_| &mut phases));
    if let Some(times) = times {
        times[1] = phases.read_us;
        times[2] = phases.eval_us;
    }
    result
}

fn eval_script<'js>(ctx: rquickjs::Ctx<'js>, script: &str) -> anyhow::Result<Value<'js>> {
    let mut options = EvalOptions::default();
    options.global = true;
    options.strict = false;
    match ctx.eval_with_options::<Value, _>(script, options) {
        Ok(value) => Ok(value),
        Err(error) => {
            if let Some(exception) = ctx.catch().into_exception() {
                Err(anyhow::anyhow!("JS Exception: {:?}", exception))
            } else {
                Err(anyhow::anyhow!("JS eval error: {error:?}"))
            }
        }
    }
}

fn active_js_lib_script() -> anyhow::Result<String> {
    let js_lib = ACTIVE_JS_LIB.with(|cell| cell.borrow().clone());
    let Some(js_lib) = js_lib.filter(|value| !value.trim().is_empty()) else {
        return Ok(String::new());
    };
    // Plain inline source needs only trimming, not content hashing or a
    // second cached copy. It is still evaluated in each fresh Context.
    // Keep JSON-object libraries on the existing URL/session cache path.
    let trimmed = js_lib.trim();
    if !trimmed.starts_with('{') {
        return Ok(if trimmed.len() == js_lib.len() {
            js_lib
        } else {
            trimmed.to_string()
        });
    }
    let cache_key = md5_hex(&js_lib);
    // A remote library can depend on a user's cookies. Keep it in the active
    // operation only; a process-global cache would expose one user's script
    // to another user of the same book source.
    let remote = serde_json::from_str::<JsonValue>(&js_lib)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .is_some_and(|map| {
            map.values()
                .filter_map(JsonValue::as_str)
                .any(is_absolute_http_url)
        });
    if remote {
        let active = current_active_session();
        if let Some(cached) = active
            .as_ref()
            .and_then(|session| session.script_cache_get(&cache_key))
        {
            return Ok(cached);
        }
        let compiled = compile_js_lib(&js_lib)?;
        if let Some(session) = active {
            session.script_cache_put(cache_key, compiled.clone());
        }
        return Ok(compiled);
    }
    if let Some(cached) = JS_LIB_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&cache_key)
        .cloned()
    {
        return Ok(cached);
    }

    let compiled = compile_js_lib(&js_lib)?;
    JS_LIB_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(cache_key, compiled.clone());
    Ok(compiled)
}

fn compile_js_lib(js_lib: &str) -> anyhow::Result<String> {
    let trimmed = js_lib.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<JsonValue>(trimmed) {
            if let Some(map) = value.as_object() {
                let mut scripts = Vec::new();
                for entry in map.values().filter_map(JsonValue::as_str) {
                    if is_absolute_http_url(entry) {
                        scripts.push(resolve_js_lib_entry(entry)?);
                    }
                }
                return Ok(scripts.join("\n"));
            }
        }
    }
    Ok(trimmed.to_string())
}

fn is_absolute_http_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
}

fn java_import_script(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() || !is_absolute_http_url(path) {
        return None;
    }

    let cache_key = format!("import_script:{}", md5_hex(path));
    let active = current_active_session();
    if let Some(cached) = active
        .as_ref()
        .and_then(|session| session.script_cache_get(&cache_key))
    {
        return Some(cached);
    }
    let body = java_analyzed_request_body(path, None);
    if body.is_empty() {
        return None;
    }
    if let Some(session) = active {
        session.script_cache_put(cache_key, body.clone());
    }
    Some(body)
}

fn java_timestamp_long(ctx: &rquickjs::Ctx<'_>, timestamp: f64) -> rquickjs::Result<i64> {
    if !timestamp.is_finite()
        || !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&timestamp)
    {
        return Err(rquickjs::Exception::throw_type(
            ctx,
            "time format requires a finite Java long timestamp",
        ));
    }
    Ok(timestamp as i64)
}

fn parse_cookie_pairs(input: &str) -> HashMap<String, String> {
    input
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                return None;
            }
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn cookie_pairs_to_string(pairs: &HashMap<String, String>) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn js_cache_get(key: &str) -> Option<String> {
    if let Some(active) = current_active_session() {
        return active.js_cache_get(key);
    }
    let mut cache = JS_CACHE.lock().unwrap_or_else(|error| error.into_inner());
    let expired = cache
        .get(key)
        .and_then(|entry| entry.expires_at)
        .is_some_and(|expires_at| Instant::now() >= expires_at);
    if expired {
        cache.remove(key);
        None
    } else {
        cache.get(key).map(|entry| entry.value.clone())
    }
}

fn js_cache_put(key: &str, value: String, save_time_secs: Option<i64>) -> bool {
    if let Some(active) = current_active_session() {
        return active.js_cache_put(key, value, save_time_secs);
    }
    let expires_at = save_time_secs
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| Instant::now().checked_add(Duration::from_secs(seconds as u64)));
    let mut cache = JS_CACHE.lock().unwrap_or_else(|error| error.into_inner());
    cache.insert(key.to_string(), JsCacheEntry { value, expires_at });
    true
}

fn js_cache_delete(key: &str) -> bool {
    if let Some(active) = current_active_session() {
        return active.js_cache_delete(key);
    }
    JS_CACHE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(key)
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::session::{with_active_session, ExecuteSession};
    use crate::model::book_source::BookSource;
    use crate::parser::js_http::{with_js_http_client, with_js_http_context};
    use serde_json::json;
    use std::io::{BufRead, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn invalid_login_header_throws_without_changing_session() {
        let (result, delta) = with_active_session(None, "https://example.test/", |_| {
            eval_js(
                r#"source.putLoginHeader('{"Cookie":"sid=old","Authorization":"old"}');
                let rejected = false;
                try { source.putLoginHeader('{"Cookie":"sid=new; broken"}'); }
                catch (error) { rejected = error instanceof TypeError; }
                [rejected, source.getLoginHeaderMap().get('Authorization'), cookie.getKey('', 'sid')].join('|')"#,
                "", "https://example.test/",
            ).unwrap()
        });
        assert_eq!(result, "true|old|old");
        assert!(delta.is_some());
    }

    #[test]
    fn scoped_js_contexts_restore_after_nested_unwind() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        assert!(ACTIVE_JS_LIB.with(|cell| cell.borrow().is_none()));
        with_js_lib(Some("outer"), || {
            let result: Result<(), ()> = with_js_lib(None, || Err(()));
            assert_eq!(result, Err(()));
            assert!(catch_unwind(AssertUnwindSafe(|| {
                with_js_lib(Some("inner"), || panic!("expected"));
            }))
            .is_err());
            assert_eq!(
                ACTIVE_JS_LIB.with(|cell| cell.borrow().clone()),
                Some("outer".into())
            );
        });
        assert!(ACTIVE_JS_LIB.with(|cell| cell.borrow().is_none()));

        let client = HttpClient::standalone();
        let outer = BookSource {
            book_source_url: "https://outer.test".into(),
            ..Default::default()
        };
        let inner = BookSource {
            book_source_url: "https://inner.test".into(),
            ..Default::default()
        };
        assert!(catch_unwind(AssertUnwindSafe(|| {
            with_js_http_context(&client, &outer, || {
                assert!(catch_unwind(AssertUnwindSafe(|| {
                    with_js_http_context(&client, &inner, || {
                        assert!(ACTIVE_JS_HTTP_CONTEXT.with(|cell| cell.borrow().is_some()));
                        panic!("expected");
                    });
                }))
                .is_err());
                assert_eq!(
                    ACTIVE_JS_BOOK_SOURCE.with(|cell| cell
                        .borrow()
                        .as_ref()
                        .unwrap()
                        .book_source_url
                        .clone()),
                    outer.book_source_url
                );
                assert!(ACTIVE_JS_HTTP_CONTEXT.with(|cell| cell.borrow().is_some()));
                panic!("expected");
            });
        }))
        .is_err());
        assert!(ACTIVE_JS_HTTP_CONTEXT.with(|cell| cell.borrow().is_none()));
        assert!(ACTIVE_JS_BOOK_SOURCE.with(|cell| cell.borrow().is_none()));

        let runtime = Runtime::new().unwrap();
        let outer_ctx = Context::full(&runtime).unwrap();
        let inner_runtime = Runtime::new().unwrap();
        let inner_ctx = Context::full(&inner_runtime).unwrap();
        outer_ctx.with(|outer| {
            with_js_reentrant_ctx(&outer, || {
                inner_ctx.with(|inner| {
                    assert!(catch_unwind(AssertUnwindSafe(|| {
                        with_js_reentrant_ctx(&inner, || {
                            assert_eq!(
                                ACTIVE_JS_REENTRANT_CTX.with(|cell| *cell.borrow()),
                                Some(inner.as_raw())
                            );
                            panic!("expected");
                        });
                    }))
                    .is_err());
                });
                assert_eq!(
                    ACTIVE_JS_REENTRANT_CTX.with(|cell| *cell.borrow()),
                    Some(outer.as_raw())
                );
            });
        });
        assert!(ACTIVE_JS_REENTRANT_CTX.with(|cell| cell.borrow().is_none()));
    }

    fn accept_with_timeout(listener: &TcpListener) -> (TcpStream, SocketAddr) {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, address)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    return (stream, address);
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("test HTTP server did not receive request: {error}"),
            }
        }
    }

    #[test]
    fn js_lib_json_object_loads_only_absolute_urls_and_uses_cache() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/shared.js");
        let marker = format!("shared_lib_{}", address.port());
        let script = format!("globalThis.{marker}=41;");
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{script}",
                script.len()
            )
            .unwrap();
        });
        let js_lib = serde_json::json!({
            "remote": url,
            "inline": "throw new Error('inline value must be ignored')",
            "relative": "/not-a-script.js"
        })
        .to_string();

        with_active_session(None, &url, |_| {
            with_js_lib(Some(&js_lib), || {
                let expression = format!("{marker} + 1");
                assert_eq!(eval_js(&expression, "", &url).unwrap(), "42");
                assert_eq!(eval_js(&expression, "", &url).unwrap(), "42");
            });
        });
        server.join().unwrap();
        assert_eq!(
            compile_js_lib(r#"{"inline":"var notLoaded=1"}"#).unwrap(),
            ""
        );
    }

    #[test]
    fn inline_js_lib_const_functions_survive_repeated_rules_without_cross_source_leaks() {
        // 爱发电 / 引力圈 use a top-level `const urlsData` plus helper functions.
        let first =
            "const urlsData = ['ifdian.net']; function getSourceHost() { return urlsData[0]; }";
        let second = "const urlsData = ['app2.unifans.io']; function getSourceHost() { return urlsData[0]; }";
        with_js_lib(Some(first), || {
            assert_eq!(
                eval_js("getSourceHost()", "", "https://example.com").unwrap(),
                "ifdian.net"
            );
            assert_eq!(
                eval_js("getSourceHost()", "", "https://example.com").unwrap(),
                "ifdian.net"
            );
        });
        with_js_lib(Some(second), || {
            assert_eq!(
                eval_js("getSourceHost()", "", "https://example.com").unwrap(),
                "app2.unifans.io"
            );
        });
        assert_eq!(
            eval_js("typeof getSourceHost", "", "https://example.com").unwrap(),
            "undefined"
        );
    }

    #[test]
    fn remote_js_lib_is_not_shared_between_sessions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/user-library.js");
        let library = serde_json::json!({"remote": url}).to_string();
        let server = thread::spawn(move || {
            for user in ["userA", "userB"] {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request);
                let body = format!("globalThis.scopedLibraryValue = '{user}';");
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        with_js_lib(Some(&library), || {
            with_active_session(None, &url, |_| {
                assert_eq!(eval_js("scopedLibraryValue", "", &url).unwrap(), "userA");
                assert_eq!(eval_js("scopedLibraryValue", "", &url).unwrap(), "userA");
            });
            with_active_session(None, &url, |_| {
                assert_eq!(eval_js("scopedLibraryValue", "", &url).unwrap(), "userB");
            });
        });
        server.join().unwrap();
    }

    #[test]
    fn java_archive_input_preserves_binary_and_source_header_plan() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                request.push_str(&line);
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\x00\xff\x80\x01").unwrap();
            request.to_ascii_lowercase()
        });
        let source = BookSource {
            book_source_url: base.clone(),
            header: Some(r#"{"X-Source":"source"}"#.to_owned()),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let state = ExecuteSession {
            header: Some(json!({"X-Login":"login"})),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let target = format!(r#"{base}/binary,{{"headers":{{"X-Option":"yes"}}}}"#);
        let (payload, _) = with_active_session(Some(&state), &base, |_| {
            with_js_http_context(&client, &source, || java_archive_input(&target))
        });
        let result: JsonValue = serde_json::from_str(&payload).unwrap();
        assert_eq!(result["data"], json!([0, 255, 128, 1]));
        let request = server.join().unwrap();
        for header in ["x-source: source", "x-login: login", "x-option: yes"] {
            assert!(request.contains(header), "{request}");
        }
        let offline: JsonValue = serde_json::from_str(&crate::host_services::with_offline(|| {
            java_archive_input(&base)
        }))
        .unwrap();
        assert_eq!(offline["error"]["kind"], "network_error");
    }

    #[test]
    fn java_zip_text_detects_encoding_and_respects_explicit_charset() {
        let text = "这是一段中文小说内容，测试压缩文件字符编码自动识别。";
        let gbk = encoding_rs::GBK.encode(text).0.into_owned();
        let script = format!(
            r#"(() => {{
                const inputs = {{gbk: {gbk}, utf8: {utf8}, bom: [255,254,45,78,135,101], empty: []}};
                java.getZipByteArrayContent = (_, path) => path === 'missing' ? null : inputs[path];
                const read = (path, charset) => java.getZipStringContent([], path, charset);
                let invalid;
                try {{ read('gbk', 'not-a-charset'); }} catch (e) {{ invalid = e.kind; }}
                return JSON.stringify([
                    read('gbk'), read('gbk', 'GBK'), read('utf8'), read('bom'),
                    read('empty'), read('missing'), read('gbk', 'UTF-8') !== read('gbk'), invalid,
                    java.bytesToStr(inputs.gbk, 'UTF-8') === read('gbk', 'UTF-8')
                ]);
            }})()"#,
            gbk = serde_json::to_string(&gbk).unwrap(),
            utf8 = serde_json::to_string(text.as_bytes()).unwrap(),
        );
        let result = eval_js(&script, "", "https://example.com").unwrap();
        assert_eq!(
            serde_json::from_str::<JsonValue>(&result).unwrap(),
            json!([
                text,
                text,
                text,
                "中文",
                "",
                "",
                true,
                "invalid_argument",
                true
            ])
        );
    }

    #[test]
    fn java_security_facade_validates_specs_states_and_overloads() {
        let result = eval_js(
            r#"(() => {
                const j = new JavaImporter();
                j.importPackage(Packages.java.security, Packages.java.security.spec);
                const source = [-1, 0, 127];
                const spec = new j.PKCS8EncodedKeySpec(source);
                source[0] = 0; spec.getEncoded()[0] = 0;
                const s = j.Signature.getInstance('SHA256withRSA');
                const f = j.KeyFactory.getInstance('RSA');
                let count = 0;
                for (const action of [
                    () => s.sign(), () => s.verify([]), () => s.update([1]),
                    () => s.initSign({}), () => f.generatePrivate(spec),
                    () => f.generatePublic(new j.X509EncodedKeySpec([48,0])),
                    () => new j.PKCS8EncodedKeySpec([NaN]),
                    () => new j.PKCS8EncodedKeySpec([256]),
                    () => j.Signature.getInstance('SHA256withRSA','provider'),
                    () => s.sign([]), () => s.update([1],0)
                ]) { try { action(); } catch(e) { if (e.kind === 'invalid_argument') count++; } }
                return [spec.getEncoded().join(','),spec.getFormat(),s.getAlgorithm(),count].join('|');
            })()"#,
            "",
            "https://example.com",
        ).unwrap();
        assert_eq!(result, "255,0,127|PKCS#8|SHA256withRSA|11");
    }

    #[test]
    fn java_arrays_copy_of_preserves_bytes_padding_and_isolation() {
        let result = eval_js(
            r#"const arrays = Packages.java.util.Arrays;
            const original = [-128, 0, 255];
            const copy = arrays.copyOf(original, 3);
            copy[0] = 7;
            let rejected = 0;
            for (const [value, length] of [[null, 0], [[], -1], [[], 1.5], [[], NaN], [[], 524289]]) {
                try { arrays.copyOf(value, length); } catch (_) { rejected++; }
            }
            [original.join(','), copy.join(','), arrays.copyOf(original, 2).join(','),
             arrays.copyOf(original, 5).join(','), arrays.copyOf(original, 0).length,
             arrays.copyOf(new Uint8Array([128, 255]), 2).join(','), rejected].join('|')"#,
            "",
            "https://example.com/",
        ).unwrap();
        assert_eq!(
            result,
            "-128,0,255|7,0,255|-128,0|-128,0,255,0,0|0|128,255|5"
        );
    }

    #[test]
    fn java_hash_map_keeps_native_map_and_header_keys_intact() {
        let result = eval_js(
            r#"const j = new JavaImporter(Packages.java.util);
            const map = new j.HashMap();
            const initial = map.put('get', 'one');
            const previous = map.put('get', 'two');
            map.put('__proto__', 'header');
            [initial === null, previous, map.get('missing') === null,
             map.get('get'), JSON.stringify(map),
             new j.HashMap().get('get') === null,
             new Map().get('missing') === undefined,
             Map.prototype.put === undefined].join('|')"#,
            "",
            "https://example.com/",
        )
        .unwrap();
        assert_eq!(
            result,
            "true|one|true|two|{\"get\":\"two\",\"__proto__\":\"header\"}|true|true|true"
        );
    }

    #[test]
    fn java_byte_buffer_exposes_fresh_zeroed_backing_arrays() {
        let result = eval_js(
            r#"const j = new JavaImporter(Packages.java.nio);
            const buffer = j.ByteBuffer.allocate(32);
            const bytes = buffer.array();
            bytes[0] = -128;
            const fresh = j.ByteBuffer.allocate(32).array();
            let rejected = 0;
            for (const size of [-1, 1.5, NaN, Infinity, 262145]) {
                try { j.ByteBuffer.allocate(size); } catch (_) { rejected++; }
            }
            [bytes === buffer.array(), bytes.length, buffer.array()[0],
             fresh.every(value => value === 0), j.ByteBuffer.allocate(0).array().length,
             rejected].join('|')"#,
            "",
            "https://example.com",
        )
        .unwrap();
        assert_eq!(result, "true|32|-128|true|0|5");
    }

    #[test]
    fn java_memory_streams_preserve_ranges_eof_and_close_semantics() {
        let result = eval_js(
            r#"
            const j = new JavaImporter(Packages.java.io);
            const input = new j.ByteArrayInputStream([9,255,1,2],1,3);
            const buffer = [0,0,0,0];
            const count = input.read(buffer,1,2);
            input.close();
            const output = new j.ByteArrayOutputStream();
            output.write(buffer,1,count); output.write(input.read()); output.close();
            [count,output.toByteArray().join(','),input.read(),input.read([],0,0)].join('|')
        "#,
            "",
            "https://example.com",
        )
        .unwrap();
        assert_eq!(result, "2|255,1,2|-1|0");
    }

    #[test]
    fn audit_get_source_preserves_source_identity_and_absence() {
        let url = "https://example.com";
        assert_eq!(
            eval_js("java.getSource() === null", "", url).unwrap(),
            "true"
        );
        let source = BookSource {
            book_source_url: url.to_string(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        assert_eq!(
            with_js_http_context(&client, &source, || {
                eval_js("java.getSource() === source && java.getSource().getKey() === 'https://example.com'", "", url).unwrap()
            }),
            "true"
        );
        assert_eq!(
            eval_js("java.getSource() === null", "", url).unwrap(),
            "true"
        );
    }

    #[test]
    fn login_get_str_response_false_uses_direct_http_even_for_webview_spec() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let first_line = crate::util::test_http::consume_request(&mut stream);
            let body = "direct-http";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            first_line
        });
        let source = BookSource {
            book_source_url: base.clone(),
            ..Default::default()
        };
        let mut spec =
            crate::crawler::analyze_url(&format!("{base}/retry"), "", 1, &base, &source).unwrap();
        // Avoid invoking a browser in this test: directly exercise the
        // loginCheckJs retry bridge with a prepared WebView-enabled spec.
        spec.render_with_rakers = true;
        let client = HttpClient::standalone();
        let output = with_js_http_context(&client, &source, || {
            with_login_check_request(
                &spec,
                &format!("{base}/retry"),
                "",
                1,
                &base,
                &source,
                None,
                || {
                    eval_js(
                        r#"let blocked = false;
                       try { java.getStrResponse(); } catch (e) {
                         blocked = String(e).includes('WebView retry is not supported');
                       }
                       const response = java.getStrResponse(null, null, false);
                       [blocked, response.code(), response.body(), response.url()].join('|')"#,
                        "",
                        &base,
                    )
                    .unwrap()
                },
            )
        });
        assert_eq!(output, format!("true|200|direct-http|{base}/retry"));
        assert!(server.join().unwrap().starts_with("GET /retry "));
        assert_eq!(
            eval_js("typeof java.getStrResponse", "", &base).unwrap(),
            "undefined"
        );
    }

    #[test]
    fn login_get_user_agent_reads_prepared_request_only_in_login_scope() {
        let base = "https://login-agent.example";
        let source = BookSource {
            book_source_url: base.into(),
            header: Some(
                r#"js:JSON.stringify({"User-Agent":source.getVariable() || "Reader-Custom/1"})"#
                    .into(),
            ),
            ..Default::default()
        };
        let spec = crate::crawler::analyze_url(base, "", 1, base, &source).unwrap();
        let client = HttpClient::standalone();
        let output = with_js_http_context(&client, &source, || {
            with_login_check_request(&spec, base, "", 1, base, &source, None, || {
                eval_js(
                    r#"const first = java.getUserAgent();
                       source.setVariable("Reader-Custom/2");
                       java.initUrl();
                       [first, java.getUserAgent(),
                        java.getUserAgent() !== java.getWebViewUA()].join('|')"#,
                    "",
                    base,
                )
                .unwrap()
            })
        });
        assert_eq!(output, "Reader-Custom/1|Reader-Custom/2|true");
        assert_eq!(
            eval_js("typeof java.getUserAgent", "", base).unwrap(),
            "undefined"
        );
    }

    #[test]
    fn login_init_url_failure_keeps_previous_prepared_request() {
        let base = "https://login.example";
        let source = BookSource {
            book_source_url: base.into(),
            ..Default::default()
        };
        let raw_rule = "@js:source.getVariable() === 'bad' ? 'mailto:failed' : baseUrl + '/ready'";
        let spec = crate::crawler::analyze_url(raw_rule, "", 1, base, &source).unwrap();
        let client = HttpClient::standalone();
        with_js_http_context(&client, &source, || {
            with_login_check_request(&spec, raw_rule, "", 1, base, &source, None, || {
                let output = eval_js(
                    r#"source.setVariable('good');
                           java.initUrl();
                           const originalUrl = java.url;
                           const originalRule = java.ruleUrl;
                           source.setVariable('bad');
                           let failed = false;
                           try { java.initUrl(); } catch (e) { failed = true; }
                           [failed, java.url === originalUrl,
                            java.ruleUrl === originalRule].join('|')"#,
                    "",
                    base,
                )
                .unwrap();
                assert_eq!(output, "true|true|true");
                assert_eq!(
                    active_login_check_request().unwrap().url,
                    format!("{base}/ready")
                );
            })
        });
        assert_eq!(
            eval_js("typeof java.initUrl", "", base).unwrap(),
            "undefined"
        );
    }

    #[test]
    fn source_login_runs_script_without_overwriting_outer_js() {
        let source = BookSource {
            book_source_url: "https://source-login.example".into(),
            login_url: Some(
                "function login() { source.put('login-test', 'done'); result = 'changed'; }".into(),
            ),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let output = with_js_http_context(&client, &source, || {
            eval_js(
                "let original = result; let returned = source.login(); [returned === undefined, result === original, source.get('login-test'), typeof login].join('|')",
                "outer", &source.book_source_url,
            )
            .unwrap()
        });
        assert_eq!(output, "true|true|done|undefined");
        assert_eq!(
            eval_js(
                "source.login() === undefined",
                "",
                "https://empty-login.example"
            )
            .unwrap(),
            "true"
        );
    }

    #[test]
    fn source_login_reuses_http_cookies_and_source_variable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut login, _) = accept_with_timeout(&listener);
            let first = crate::util::test_http::consume_request(&mut login);
            let token = r#"{"token":"new-token"}"#;
            write!(
                login,
                "HTTP/1.1 200 OK\r\nSet-Cookie: sid=from-login; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{token}",
                token.len()
            )
            .unwrap();
            let (mut book, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(&mut book);
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                headers.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            drop(reader);
            let content = "book-loaded";
            write!(
                book,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{content}",
                content.len()
            )
            .unwrap();
            (first, headers)
        });
        let source = BookSource {
            book_source_url: base.clone(),
            login_url: Some(format!(
                "function login() {{ let response = JSON.parse(java.ajax('{base}/login')); source.setVariable(response.token); }}"
            )),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let output = with_js_http_context(&client, &source, || {
            eval_js(
                &format!(
                    "let saved = result; source.login(); let response = java.connect('{base}/book'); [result === saved, source.getVariable(), response.body()].join('|')"
                ),
                "original", &base,
            )
            .unwrap()
        });
        assert_eq!(output, "true|new-token|book-loaded");
        let (first, second) = server.join().unwrap();
        assert!(first.starts_with("GET /login "), "{first}");
        assert!(second.starts_with("GET /book "), "{second}");
        assert!(
            second
                .to_ascii_lowercase()
                .contains("cookie: sid=from-login"),
            "{second}"
        );
    }

    #[test]
    fn source_login_propagates_errors_and_resets_recursion_guard() {
        let client = HttpClient::standalone();
        let recursive = BookSource {
            book_source_url: "https://recursive-login.example".into(),
            login_url: Some("function login() { source.login(); }".into()),
            ..Default::default()
        };
        let output = with_js_http_context(&client, &recursive, || {
            eval_js(
                "let failed = false; try { source.login() } catch(e) { failed = true }; let failedAgain = false; try { source.login() } catch(e) { failedAgain = true }; [failed, failedAgain].join('|')",
                "", &recursive.book_source_url,
            ).unwrap()
        });
        assert_eq!(output, "true|true");

        let missing = BookSource {
            book_source_url: "https://missing-login.example".into(),
            login_url: Some("const flag = true;".into()),
            ..Default::default()
        };
        let output = with_js_http_context(&client, &missing, || {
            eval_js(
                "try { source.login(); 'unexpected' } catch(e) { String(e).includes('login not implements') }",
                "", &missing.book_source_url,
            ).unwrap()
        });
        assert_eq!(output, "true");

        let browser = BookSource {
            book_source_url: "https://browser-login.example".into(),
            login_url: Some("https://example.com/login".into()),
            ..Default::default()
        };
        let output = with_js_http_context(&client, &browser, || {
            eval_js(
                "try { source.login(); 'unexpected' } catch(e) { String(e).includes('browser login URLs') }",
                "", &browser.book_source_url,
            ).unwrap()
        });
        assert_eq!(output, "true");
    }

    #[test]
    fn source_get_header_map_uses_source_rules_and_optional_login() {
        let url = "https://headers.example";
        let client = HttpClient::standalone();
        let source = BookSource {
            book_source_url: url.to_string(),
            header: Some(r#"{"X-Source":"source","X-Order":"source"}"#.to_string()),
            ..Default::default()
        };
        let session = ExecuteSession {
            header: Some(json!({"X-Order":"login","X-Login":"secret","User-Agent":"login-agent"})),
            ..Default::default()
        };
        let (result, delta) = with_active_session(Some(&session), url, |_| {
            with_js_http_context(&client, &source, || {
                eval_js(
                    r#"const base = source.getHeaderMap();
                       const login = source.getHeaderMap(true);
                       [base instanceof Map, base.get('X-Source'), base.get('X-Order'),
                        base.has('X-Login'), base.has('User-Agent'),
                        base.get('User-Agent') !== 'login-agent',
                        login.get('X-Order'), login.get('X-Login'),
                        login.get('User-Agent'), base.get('X-Order'), login !== base].join('|')"#,
                    "",
                    url,
                )
                .unwrap()
            })
        });
        assert_eq!(
            result,
            "true|source|source|false|true|true|login|secret|login-agent|source|true"
        );
        assert!(
            delta.is_none(),
            "reading headers must not change session state"
        );

        let dynamic = BookSource {
            book_source_url: url.to_string(),
            header: Some("@js:JSON.stringify({'X-Dynamic': source.getKey()})".into()),
            ..Default::default()
        };
        let result = with_js_http_context(&client, &dynamic, || {
            eval_js("source.getHeaderMap().get('X-Dynamic')", "", url).unwrap()
        });
        assert_eq!(result, url);

        let xml_js = BookSource {
            book_source_url: url.to_string(),
            header: Some("<js>JSON.stringify({'X-Tag':'yes'})</js>".into()),
            ..Default::default()
        };
        let result = with_js_http_context(&client, &xml_js, || {
            eval_js("source.getHeaderMap().get('X-Tag')", "", url).unwrap()
        });
        assert_eq!(result, "yes");

        let invalid = BookSource {
            book_source_url: url.to_string(),
            header: Some("@js:throw new Error('invalid header')".into()),
            ..Default::default()
        };
        let result = with_js_http_context(&client, &invalid, || {
            eval_js(
                "const map = source.getHeaderMap(); map instanceof Map && map.has('User-Agent') && map.size === 1",
                "", url,
            ).unwrap()
        });
        assert_eq!(result, "true");

        let recursive = BookSource {
            book_source_url: url.to_string(),
            header: Some("@js:source.getHeaderMap()".into()),
            ..Default::default()
        };
        let result = with_js_http_context(&client, &recursive, || {
            eval_js(
                r#"const first = source.getHeaderMap();
                   const second = source.getHeaderMap();
                   [first.has('User-Agent'), second.has('User-Agent'),
                    first.size, second.size].join('|')"#,
                "",
                url,
            )
            .unwrap()
        });
        assert_eq!(result, "true|true|1|1");
    }

    #[test]
    fn java_has_java_class_checks_registered_compatibility_classes() {
        assert_eq!(
            eval_js(
                r#"typeof java.hasJavaClass === 'function'
                    && java.hasJavaClass('java.lang.String') === true
                    && java.hasJavaClass('android.util.Base64') === true
                    && java.hasJavaClass('java.net.URL') === true
                    && java.hasJavaClass('okhttp3.HttpUrl') === true
                    && java.hasJavaClass('java.lang') === false
                    && java.hasJavaClass('missing.Class') === false
                    && java.hasJavaClass('java.lang.String.prototype') === false
                    && java.hasJavaClass('java.lang.__proto__') === false
                    && java.hasJavaClass('org.jsoup.Jsoup') === false
                    && java.hasJavaClass() === false
                    && java.hasJavaClass(null) === false
                    && java.hasJavaClass(123) === false"#,
                "",
                "https://example.com"
            )
            .unwrap(),
            "true"
        );
    }

    #[test]
    fn java_get_tag_reads_current_source_name_without_leaking_context() {
        let url = "https://example.com";
        assert_eq!(eval_js("java.getTag() === null", "", url).unwrap(), "true");

        let source = BookSource {
            book_source_url: url.to_string(),
            book_source_name: "测试书源".to_string(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        assert_eq!(
            with_js_http_context(&client, &source, || {
                eval_js("java.getTag()", "", url).unwrap()
            }),
            "测试书源"
        );

        let other = BookSource {
            book_source_url: "https://other.example".to_string(),
            book_source_name: "Other".to_string(),
            ..Default::default()
        };
        assert_eq!(
            with_js_http_context(&client, &other, || {
                eval_js("java.getTag()", "", &other.book_source_url).unwrap()
            }),
            "Other"
        );
        assert_eq!(eval_js("java.getTag() === null", "", url).unwrap(), "true");
    }

    #[test]
    fn source_get_tag_uses_name_without_url_fallback() {
        let url = "https://example.com";
        assert_eq!(
            eval_js("source.getTag() === null", "", url).unwrap(),
            "true"
        );

        let source = BookSource {
            book_source_url: url.to_string(),
            book_source_name: "测试书源".to_string(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        assert_eq!(
            with_js_http_context(&client, &source, || {
                eval_js(
                    "source.getTag() === '测试书源' && source.getTag() === java.getTag()",
                    "",
                    url,
                )
                .unwrap()
            }),
            "true"
        );

        let unnamed = BookSource {
            book_source_url: url.to_string(),
            ..Default::default()
        };
        assert_eq!(
            with_js_http_context(&client, &unnamed, || {
                eval_js(
                    "source.getTag() === '' && source.getTag() !== source.getKey()",
                    "",
                    url,
                )
                .unwrap()
            }),
            "true"
        );
        assert_eq!(
            eval_js("source.getTag() === null", "", url).unwrap(),
            "true"
        );
    }

    #[test]
    fn audit_log_preserves_input_type_and_object_identity() {
        assert_eq!(eval_js(
            "const obj = {value: 1}; [java.log(obj) === obj, java.log(42) === 42, java.log(true) === true, java.log(null) === null, java.log() === undefined, java.log('text') === 'text'].join('|')",
            "", "https://example.com"
        ).unwrap(), "true|true|true|true|true|true");
        assert_eq!(
            eval_js(
                "result = java.log('new content'); result",
                "old",
                "https://example.com"
            )
            .unwrap(),
            "new content"
        );
    }

    #[test]
    fn java_log_coerces_numbers_and_other_values_to_strings() {
        let result = eval_js(
            r#"java.log(1700000000.125); java.log(true); java.log({ timestamp: 1700000000 }); java.log(null); java.log(); 'ok'"#,
            "",
            "https://example.com",
        )
        .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn low_risk_compat_apis_cover_headers_encodings_cache_and_utc_time() {
        let cache_key = format!("js-compat-{}", generate_uuid_v4());
        let script = format!(
            r#"
                const bytes = java.strToBytes('中文', 'GBK');
                const decoded = java.bytesToStr(bytes, 'GBK');
                const encoded = java.encodeURI('中文', 'GBK');
                const formEncoded = java.encodeURI('a b/c~');
                const b64 = java.base64Decode('5Lit5paH', 'UTF-8');
                const hex = java.hexEncodeToString('reader');
                const hexBytes = java.hexDecodeToByteArray(hex).join(',');
                const hexText = java.hexDecodeToString(hex);
                const digestAlias = java.md5Encode16('reader') === java.md5To16('reader');
                const utc = java.timeFormatUTC(0, "yyyy-MM-dd HH:mm:ss.SSS", 28800000);
                const localFormat = /^\d{{4}}\/\d{{2}}\/\d{{2}} \d{{2}}:\d{{2}}$/.test(java.timeFormat(0));
                cache.put('{cache_key}', 'cached', 60);
                const cached = cache.get('{cache_key}');
                const removed = cache.delete('{cache_key}');
                [decoded, encoded, formEncoded, b64, hex, hexBytes, hexText, digestAlias, utc,
                 localFormat, cached, typeof removed === 'undefined',
                 cache.get('{cache_key}') === null].join('|');
            "#
        );
        let output = eval_js(&script, "", "https://example.com").unwrap();
        assert_eq!(
            output,
            "中文|%D6%D0%CE%C4|a+b%2Fc%7E|中文|726561646572|114,101,97,100,101,114|reader|true|1970-01-01 08:00:00.000|true|cached|true|true"
        );

        let expired_key = format!("js-expired-{}", generate_uuid_v4());
        JS_CACHE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                expired_key.clone(),
                JsCacheEntry {
                    value: "stale".to_string(),
                    expires_at: Some(Instant::now() - Duration::from_secs(1)),
                },
            );
        let expired = eval_js(
            &format!("cache.get('{expired_key}') === null"),
            "",
            "https://example.com",
        )
        .unwrap();
        assert_eq!(expired, "true");
    }

    #[test]
    fn memory_cache_spellings_keep_values_in_operation_only() {
        let url = "https://memory-cache.example/books";
        let (value, delta) = with_active_session(None, url, |_| {
            eval_js(
                "cache.putMemory('item', {count: 2}); cache.getFromMemory('item').count",
                "",
                url,
            )
            .unwrap();
            eval_js("cache.getFromMemory('item').count", "", url).unwrap()
        });
        assert_eq!(value, "2");
        assert!(
            delta.is_none(),
            "memory cache must not change the session DTO"
        );
        let (isolated, _) = with_active_session(None, url, |_| {
            eval_js("cache.getFromMemory('item') === null", "", url).unwrap()
        });
        assert_eq!(isolated, "true");
        let (deleted, _) = with_active_session(None, url, |_| {
            eval_js(
                "cache.putMemory('item', 'text'); cache.deleteMemory('item'); cache.getFromMemory('item') === null",
                "",
                url,
            )
            .unwrap()
        });
        assert_eq!(deleted, "true");
    }

    #[test]
    fn js_cache_is_isolated_by_session_and_restored_from_session_delta() {
        let url = "https://same-source.example/books";
        let key = format!("session-cache-{}", generate_uuid_v4());
        let (value, saved) = with_active_session(None, url, |_| {
            eval_js(
                &format!("cache.put('{key}', 'user-a', 60); cache.get('{key}')"),
                "",
                url,
            )
            .unwrap()
        });
        assert_eq!(value, "user-a");
        let saved = saved.expect("cache write must be returned to the caller");
        let (other_user, delta) = with_active_session(None, url, |_| {
            eval_js(&format!("cache.get('{key}') === null"), "", url).unwrap()
        });
        assert_eq!(other_user, "true");
        assert!(delta.is_none());
        let (restored, _) = with_active_session(Some(&saved), url, |_| {
            eval_js(&format!("cache.get('{key}')"), "", url).unwrap()
        });
        assert_eq!(restored, "user-a");

        let (kv_saved, kv_state) = with_active_session(None, url, |_| {
            eval_js("kv_put('private', 'user-a'); kv_get('private')", "", url).unwrap()
        });
        assert_eq!(kv_saved, "user-a");
        let (kv_other, _) = with_active_session(None, url, |_| {
            eval_js("kv_get('private') == null", "", url).unwrap()
        });
        assert_eq!(kv_other, "true");
        let (kv_restored, _) = with_active_session(kv_state.as_ref(), url, |_| {
            eval_js("kv_get('private')", "", url).unwrap()
        });
        assert_eq!(kv_restored, "user-a");

        let (large_page, state) = with_active_session(None, url, |_| {
            eval_js(
                &format!("cache.put('{key}', 'x'.repeat(126057)); cache.get('{key}').length"),
                "",
                url,
            )
            .unwrap()
        });
        assert_eq!(large_page, "126057");
        let (restored, _) = with_active_session(state.as_ref(), url, |_| {
            eval_js(&format!("cache.get('{key}').length"), "", url).unwrap()
        });
        assert_eq!(restored, "126057");

        let (oversized, _) = with_active_session(None, url, |_| {
            eval_js(&format!("cache.put('{key}', 'x'.repeat(262145))"), "", url)
        });
        assert!(oversized
            .unwrap_err()
            .to_string()
            .contains("session cache limit exceeded"));
    }

    #[test]
    fn java_connect_returns_str_response_for_http_and_transport_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                request.push_str(&line);
            }
            write!(
                stream,
                "HTTP/1.1 418 I'm a teapot\r\nContent-Type: application/json\r\nX-Connect: yes\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied"
            )
            .unwrap();
            request.to_ascii_lowercase()
        });

        let url = format!("http://{address}/connect");
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let script = format!(
            r#"
                const response = java.connect('{url}', {{'X-Request':'connect'}});
                [response.__ffiStrResponse, response.code(), response.message(),
                 response.url(), response.body(), response.isSuccessful(),
                 response.headers().get('x-connect'), response.raw().code(),
                 String(response).includes('code=418')].join('|');
            "#
        );
        let result = with_js_http_context(&client, &source, || eval_js(&script, "", &url).unwrap());
        assert_eq!(
            result,
            format!("true|418|I'm a teapot|{url}|denied|false|yes|418|true")
        );
        assert!(server.join().unwrap().contains("x-request: connect"));

        let invalid = with_js_http_context(&client, &source, || {
            eval_js(
                "(() => { const response = java.connect('ftp://invalid'); return [response.code(), response.message(), response.isSuccessful(), response.url(), response.body().length > 0, response.raw().code()].join('|'); })()",
                "",
                &url,
            )
            .unwrap()
        });
        assert_eq!(invalid, "200|OK|true|http://localhost/|true|200");
    }

    #[test]
    fn java_ajax_and_connect_keep_http_errors_separate_from_transport_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/missing", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                write!(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\nConnection: close\r\n\r\nmissing").unwrap();
            }
        });
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let script = format!(
            "(() => {{ const body = java.ajax({url:?}); const response = java.connect({url:?}); return [body, response.code(), response.body(), response.isSuccessful()].join('|'); }})()"
        );
        let result = with_js_http_context(&client, &source, || eval_js(&script, "", &url).unwrap());
        assert_eq!(result, "missing|404|missing|false");
        server.join().unwrap();

        let result = with_js_http_context(&client, &source, || {
            eval_js(
                "(() => { const body = java.ajax('ftp://invalid'); const response = java.connect('ftp://invalid'); return [typeof body, body.length > 0, response.code(), response.body().length > 0].join('|'); })()",
                "", &url,
            ).unwrap()
        });
        assert_eq!(result, "string|true|200|true");
    }

    #[test]
    fn java_ajax_and_connect_return_values_on_broken_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/broken", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                write!(stream, "not an HTTP response\r\n").unwrap();
            }
        });
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let script = format!(
            "(() => {{ const body = java.ajax({url:?}); const response = java.connect({url:?}); return [typeof body, body.length > 0, response.code(), response.body().length > 0].join('|'); }})()"
        );
        let result = with_js_http_context(&client, &source, || eval_js(&script, "", &url).unwrap());
        assert_eq!(result, "string|true|200|true");
        server.join().unwrap();
    }

    #[test]
    fn java_connect_applies_analyze_url_body_js_without_changing_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            write!(stream, "HTTP/1.1 418 Teapot\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest").unwrap();
        });
        let url = format!("http://{address}/test");
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let script = format!(
            r#"(() => {{ const response = java.connect('{url},{{"bodyJs":"result.toUpperCase()"}}'); return response.code() + '|' + response.body(); }})()"#
        );
        let result = with_js_http_context(&client, &source, || eval_js(&script, "", &url).unwrap());
        assert_eq!(result, "418|TEST");
        server.join().unwrap();
    }

    #[test]
    fn p2_ajax_test_all_preserves_batch_shape_and_validates_timeout() {
        let result = eval_js(
            r#"
            const calls = [];
            java.__nativeAjaxTestAllItem = (url, timeout) => {
                calls.push([url, timeout]);
                return JSON.stringify({url, body: url, code: 201, callTime: 12, errorBody: null});
            };
            const responses = java.ajaxTestAll(['one', 'two'], 1500, true);
            let rejected = 0;
            for (const timeout of [undefined, null, 0, -1, 120001, '1500']) {
                try { java.ajaxTestAll([], timeout); }
                catch (error) { if (error instanceof TypeError) rejected++; }
            }
            JSON.stringify([responses.map(r => [r.code(), r.body(), r.callTime(), r.errorBody()]),
                calls, java.ajaxTestAll([], 1).length, rejected])
            "#,
            "",
            "https://example.test",
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<JsonValue>(&result).unwrap(),
            json!([
                [[201, "one", 12, null], [201, "two", 12, null]],
                [["one", 1500], ["two", 1500]],
                0,
                6
            ])
        );
    }

    #[test]
    fn p2_ajax_test_all_reuses_http_and_isolates_timeout_and_invalid_url() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for (delay, body) in [(0, "ok"), (160, "slow")] {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut request = [0; 2048];
                stream.read(&mut request).unwrap();
                thread::sleep(Duration::from_millis(delay));
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let source = BookSource {
            book_source_url: base.clone(),
            ..Default::default()
        };
        let client = HttpClient::new(1000, None, None).unwrap();
        let good = format!("{base}/good");
        let slow = format!("{base}/slow");
        let script = format!(
            r#"
            const items = java.ajaxTestAll([{good:?}, {slow:?}, 'ftp://invalid'], 30, true);
            const normal = java.ajaxAll(['ftp://invalid'])[0];
            [items.length, items[0].code(), items[0].body(),
                items[0].callTime() >= 0, items[0].errorBody() === null,
                items[1].callTime(), !!items[1].errorBody(),
                items[2].callTime(), !!items[2].errorBody(),
                normal.callTime(), normal.errorBody() === null, normal.body().length > 0].join('|')
            "#
        );
        let result =
            with_js_http_context(&client, &source, || eval_js(&script, "", &base).unwrap());
        server.join().unwrap();
        assert_eq!(result, "3|200|ok|true|true|-1|true|-7|true|0|true|true");
    }

    #[test]
    fn p2_ajax_test_all_reuses_url_options_and_restores_js_scope() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length: ") {
                    content_length = value.trim().parse().unwrap();
                }
                request.push_str(&line);
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            stream
                .write_all(b"HTTP/1.1 422 Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            (
                request.to_ascii_lowercase(),
                String::from_utf8(body).unwrap(),
            )
        });

        let source = BookSource {
            book_source_url: format!("http://{address}/source"),
            ..Default::default()
        };
        let target = format!(
            "/check,{}",
            json!({
                "method": "POST",
                "headers": {"X-Url": "configured"},
                "body": "payload",
                "js": "java.headerMap.put('X-Option','yes'); result",
                "bodyJs": "result.toUpperCase()"
            })
        );
        let script = format!(
            r#"const responses = java.ajaxTestAll([{target:?}], 1000);
            [responses.length, responses[0].code(), responses[0].body(),
                responses[0].callTime() >= 0, responses[0].errorBody() === null,
                !Object.prototype.hasOwnProperty.call(java, 'headerMap')].join('|')"#
        );
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(&script, "", &source.book_source_url).unwrap()
        });
        let (request, body) = server.join().unwrap();
        assert_eq!(result, "1|422|OK|true|true|true");
        assert!(request.starts_with("post /check "));
        assert!(request.contains("x-url: configured"));
        assert!(request.contains("x-option: yes"));
        assert_eq!(body, "payload");
    }

    #[test]
    fn java_ajax_all_runs_sequentially_preserves_order_and_isolates_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, cookie, body) in [(201, true, "first"), (502, false, "last")] {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                }
                requests.push(request.to_ascii_lowercase());
                if cookie {
                    write!(
                        stream,
                        "HTTP/1.1 {status} Created\r\nSet-Cookie: sid=ordered; Path=/\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                } else {
                    write!(
                        stream,
                        "HTTP/1.1 {status} Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                }
            }
            requests
        });

        let first = format!("http://{address}/first");
        let last = format!("http://{address}/last");
        let source = BookSource {
            book_source_url: first.clone(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(
                &format!(
                    r#"(() => {{
                        const responses = java.ajaxAll(['{first}', 'ftp://invalid', '{last}']);
                        return [responses.length, responses[0].code(), responses[0].body(),
                            responses[1].code(), responses[1].isSuccessful(), responses[1].body().length > 0,
                            responses[2].code(), responses[2].body()].join('|');
                    }})()"#
                ),
                "",
                &first,
            )
            .unwrap()
        });
        assert_eq!(result, "3|201|first|200|true|true|502|last");

        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("get /first "));
        assert!(requests[1].starts_with("get /last "));
        assert!(requests[1].contains("cookie: sid=ordered"));
    }

    #[test]
    fn p2_call_timeout_validates_before_native_request() {
        let result = eval_js(r#"
            const calls = [];
            java.__nativeAjax = (url, timeout) => { calls.push([url, timeout]); return 'ok'; };
            java.__nativeConnect = (url, headers, timeout) => {
                calls.push([url, timeout]); return JSON.stringify({body: 'ok', code: 201});
            };
            for (const timeout of [undefined, null, 1, 120000]) {
                if (java.ajax(['http://example.test'], timeout) !== 'ok'
                    || java.connect('http://example.test', {}, timeout).code() !== 201) throw new Error('valid timeout failed');
            }
            let rejected = 0;
            for (const value of [0, -1, 120001, 0.5, NaN, Infinity, -Infinity, '20', {}, [], true]) {
                for (const invoke of [() => java.ajax('http://example.test', value),
                    () => java.connect('http://example.test', {}, value)]) {
                    try { invoke(); } catch (error) { if (error instanceof TypeError) rejected++; }
                }
            }
            JSON.stringify([calls.map(call => call[1]), rejected])
        "#, "", "https://example.test").unwrap();
        assert_eq!(result, "[[null,null,null,null,1,1,120000,120000],22]");
        assert_eq!(eval_js(r#"
            let rejected = 0;
            for (const timeout of [0, 120001]) {
                try { java.__nativeAjax('http://example.test', timeout); } catch (_) { rejected++; }
                try { java.__nativeConnect('http://example.test', '', timeout); } catch (_) { rejected++; }
            }
            rejected
        "#, "", "https://example.test").unwrap(), "4");
    }

    #[test]
    fn p2_call_timeout_bounds_headers_and_body_without_leaking_defaults() {
        for analyzed in [false, true] {
            for slow_body in [false, true] {
                for connect in [false, true] {
                    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                    let url = format!("http://{}/slow", listener.local_addr().unwrap());
                    let server = thread::spawn(move || {
                        for delay in [150, 70] {
                            let (mut stream, _) = accept_with_timeout(&listener);
                            let mut request = [0; 2048];
                            stream.read(&mut request).unwrap();
                            if slow_body {
                                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n").unwrap();
                            }
                            thread::sleep(Duration::from_millis(delay));
                            let response = if slow_body {
                                "ok"
                            } else {
                                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                            };
                            let _ = stream.write_all(response.as_bytes());
                        }
                    });
                    let client = HttpClient::new(1000, None, None).unwrap();
                    let source = BookSource {
                        book_source_url: url.clone(),
                        ..Default::default()
                    };
                    let call = if connect {
                        format!("java.connect({url:?}, {{}}, 30).body()")
                    } else {
                        format!("java.ajax({url:?}, 30)")
                    };
                    let default_call = if connect {
                        format!("java.connect({url:?}, {{}}, null).body()")
                    } else {
                        format!("java.ajax({url:?})")
                    };
                    let script = format!("const started = Date.now(); const failed = {call}; const elapsed = Date.now() - started; [/timeout|timed out/i.test(failed), elapsed < 1000, {default_call}].join('|')");
                    let run = || eval_js(&script, "", &url).unwrap();
                    let result = if analyzed {
                        with_js_http_context(&client, &source, run)
                    } else {
                        with_js_http_client(&client, run)
                    };
                    server.join().unwrap();
                    assert_eq!(
                        result, "true|true|ok",
                        "analyzed={analyzed} body={slow_body} connect={connect}"
                    );
                }
            }
        }
    }

    #[test]
    fn p2_call_timeout_can_extend_defaults_including_proxy_requests() {
        for proxy in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let url = if proxy {
                "http://offline-target.invalid/slow".to_string()
            } else {
                format!("http://{address}/slow")
            };
            let server = thread::spawn(move || {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                }
                if proxy {
                    // ureq's HTTP proxy is a CONNECT tunnel, even for HTTP targets.
                    stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .unwrap();
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                        request.push_str(&line);
                    }
                }
                thread::sleep(Duration::from_millis(100));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .unwrap();
                request.to_ascii_lowercase()
            });
            let client = HttpClient::new(30, None, None).unwrap();
            let source = BookSource {
                book_source_url: url.clone(),
                ..Default::default()
            };
            let target = if proxy {
                format!(r#"{url},{{"proxy":"http://{address}"}}"#)
            } else {
                url.clone()
            };
            let script = format!("java.connect({target:?}, {{}}, 500).body()");
            let result = if proxy {
                with_js_http_context(&client, &source, || eval_js(&script, "", &url).unwrap())
            } else {
                with_js_http_client(&client, || eval_js(&script, "", &url).unwrap())
            };
            assert_eq!(result, "ok", "proxy={proxy}");
            let request = server.join().unwrap();
            if proxy {
                assert!(request.starts_with("connect offline-target.invalid:80 "));
                assert!(request.contains("get /slow "));
            }
        }
    }

    #[test]
    fn p2_call_timeout_retries_transport_timeouts_and_keeps_data_uri_local() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/retry", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for delay in [150, 0] {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut request = [0; 2048];
                stream.read(&mut request).unwrap();
                thread::sleep(Duration::from_millis(delay));
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        let client = HttpClient::standalone();
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let target = format!(r#"{url},{{"retry":1}}"#);
        let data_uri = r#"data:text/plain;base64,bG9jYWw=,{"type":"chapter"}"#;
        let result = with_js_http_context(&client, &source, || {
            eval_js(
            &format!("[java.ajax({target:?}, 100), java.connect({data_uri:?}, {{}}, 1).body()].join('|')"),
            "", &url).unwrap()
        });
        server.join().unwrap();
        assert_eq!(result, "ok|6c6f63616c");
    }

    #[test]
    fn p2_call_timeout_spans_redirects_and_keeps_cookie_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/start", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for index in 0..6 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                }
                requests.push(request.to_ascii_lowercase());
                thread::sleep(Duration::from_millis(90));
                let response = if index % 2 == 0 {
                    "HTTP/1.1 302 Found\r\nLocation: /end\r\nSet-Cookie: sid=kept; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                };
                let _ = stream.write_all(response.as_bytes());
            }
            requests
        });
        let client = HttpClient::standalone();
        let error = client
            .execute_with_call_timeout(
                ureq::http::Method::GET,
                &url,
                &[],
                None,
                Some(1024),
                Some(Duration::from_millis(150)),
            )
            .unwrap_err();
        assert!(
            matches!(error, crate::crawler::HttpClientError::Timeout(_)),
            "{error}"
        );
        // No override on this call: the first call's deadline must not leak.
        let response = client
            .execute(ureq::http::Method::GET, &url, &[], None, Some(1024))
            .unwrap();
        assert_eq!(response.body, b"ok");
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let result = with_js_http_context(&client, &source, || {
            eval_js(
                &format!("/timeout|timed out/i.test(java.connect({url:?}, {{}}, 150).body())"),
                "",
                &url,
            )
            .unwrap()
        });
        assert_eq!(result, "true");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 6);
        assert!(requests[1].starts_with("get /end "));
        assert!(requests[1].contains("cookie: sid=kept"));
        assert!(requests[2].contains("cookie: sid=kept"));
    }

    #[test]
    fn p2_call_timeout_restarts_for_retry_and_preserves_body_js_and_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/retry", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for status in [503, 200] {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                }
                requests.push(request.to_ascii_lowercase());
                thread::sleep(Duration::from_millis(90));
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                .unwrap();
            }
            requests
        });
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let client = HttpClient::new(1000, None, None).unwrap();
        let spec = format!(r#"{url},{{"retry":1,"bodyJs":"result + '!'"}}"#);
        let result = with_js_http_context(&client, &source, || {
            eval_js(
            &format!("const response = java.connect({spec:?}, {{'X-Timeout-Test':'kept'}}, 150); [response.code(), response.body()].join('|')"),
            "", &url).unwrap()
        });
        assert_eq!(result, "200|ok!");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| request.contains("x-timeout-test: kept")));
    }

    #[test]
    fn java_network_helpers_follow_analyze_url_header_precedence() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..4 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(value) = line
                        .strip_prefix("Content-Length: ")
                        .or_else(|| line.strip_prefix("content-length: "))
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                    request.push_str(&line);
                }
                let mut body = vec![0; content_length];
                reader.read_exact(&mut body).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 201 Created\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                .unwrap();
                requests.push((
                    request.to_ascii_lowercase(),
                    String::from_utf8(body).unwrap(),
                ));
            }
            requests
        });

        let url =
            r#"/ajax,{"method":"POST","headers":{"X-Url":"configured","X-Order":"url"},"body":"payload","js":"result"}"#
                .to_string();
        let script = format!(
            "(() => {{ const ajax = java.ajax([{}]); const all = java.ajaxAll([{}, {}]); const one = java.connect({}, {{'X-Order':'connect','X-Connect':'configured'}}); return [ajax, all[0].code(), all[1].code(), one.code(), all[0].body(), all[1].body(), one.body(), source.get('header-evaluation-count')].join('|'); }})()",
            serde_json::to_string(&url).unwrap(),
            serde_json::to_string(&url).unwrap(),
            serde_json::to_string(&url).unwrap(),
            serde_json::to_string(&url).unwrap()
        );
        let source = BookSource {
            book_source_url: format!("http://{address}/source"),
            header: Some(
                r#"js:const count=Number(source.get('header-evaluation-count')||'0')+1;source.put('header-evaluation-count',String(count));JSON.stringify({"X-Source":String(count),"X-Order":"source"})"#
                    .to_string(),
            ),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(&script, "", &source.book_source_url).unwrap()
        });
        assert_eq!(result, "ok|201|201|201|ok|ok|ok|3");

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 4);
        for (index, (request, body)) in requests[..3].iter().enumerate() {
            assert!(request.starts_with("post /ajax "));
            assert!(
                request.contains(&format!("x-source: {}", index + 1)),
                "source header evaluation {} was not reflected in request: {request}",
                index + 1
            );
            assert!(request.contains("x-url: configured"));
            assert!(request.contains("x-order: url"));
            assert_eq!(body, "payload");
        }

        assert!(requests[3].0.starts_with("post /ajax "));
        assert!(!requests[3].0.contains("x-source:"));
        assert!(requests[3].0.contains("x-connect: configured"));
        assert!(requests[3].0.contains("x-url: configured"));
        assert!(requests[3].0.contains("x-order: url"));
        assert_eq!(requests[3].1, "payload");
    }

    #[test]
    fn jsoup_document_remove_updates_later_select_without_leaking() {
        // Core of the local 菠萝猫 content rule: remove hidden nodes, then read paragraphs.
        let script = r#"
            var doc = org.jsoup.Jsoup.parse(result);
            doc.select("[style*='display:none']").remove();
            doc.select("[style*='display: none']").remove();
            doc.select("[style*='font-size:0']").remove();
            doc.select("[style*='font-size: 0']").remove();
            doc.select("[style*='visibility:hidden']").remove();
            doc.select("[style*='visibility: hidden']").remove();
            var paragraphs = doc.select("div.content p").toArray();
            var textList = [];
            for (var i = 0; i < paragraphs.length; i++) {
                var txt = paragraphs[i].text().trim();
                if (txt) textList.push(txt);
            }
            textList.join('\n\n');
        "#;
        let html = r#"<div class="content"><p>first</p><p style="display:none">hidden</p><p style="font-size: 0">tiny</p><div style="visibility: hidden"><p>also hidden</p></div><p>second</p></div>"#;
        assert_eq!(
            eval_js(script, html, "https://example.com").unwrap(),
            "first\n\nsecond"
        );
        let next = r#"<div class="content"><p style="display:none">secret</p><p>another</p></div>"#;
        assert_eq!(
            eval_js(script, next, "https://example.com").unwrap(),
            "another"
        );
        assert_eq!(
            eval_js("var a=org.jsoup.Jsoup.parse(result), b=org.jsoup.Jsoup.parse(result); a.select('p').remove(); a.select('p').size() + '|' + b.select('p').size()", "<p>fresh</p>", "https://example.com").unwrap(),
            "0|1"
        );
        assert!(eval_js(
            "org.jsoup.Jsoup.parse(result).select('p').first().text()",
            "<p>fresh</p>",
            "https://example.com"
        )
        .unwrap()
        .contains("fresh"));
    }

    #[test]
    fn jsoup_contains_next_page_rule_returns_url_and_absence() {
        use crate::model::rule::ContentRule;
        use crate::parser::rule_engine::RuleEngine;

        // nextContentUrl from the local 菠萝猫 source, including its URL options.
        let rule = r#"<js>
var doc = org.jsoup.Jsoup.parse(result);
var a = doc.select("div.readPage a:contains(下一页)").first();
if (a) {
    var href = a.attr("href");
    if (href && href.trim() != "") {
        var url = href.startsWith("http") ? href : "https://www.boluomao.com" + href;
        url + ',{"webView":true}';
    } else { null; }
} else { null; }
</js>"#;
        let source = BookSource {
            book_source_url: "https://www.boluomao.com".to_owned(),
            rule_content: Some(ContentRule {
                next_content_url: Some(rule.to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let engine = RuleEngine::new().unwrap();
        let base = "https://www.boluomao.com/book/1.html";
        let html = r#"<div class="readPage"><a href="/book/2.html"><span>下一页</span></a><a href="/book/3.html">下一章</a></div>"#;
        assert_eq!(
            engine.next_content_url(&source, html, base).as_deref(),
            Some("https://www.boluomao.com/book/2.html,{\"webView\":true}")
        );
        assert_eq!(
            engine.next_content_url(&source, "<div class='readPage'>完</div>", base),
            None
        );
        assert_eq!(eval_js("null", "old result", base).unwrap(), "");
        assert_eq!(
            eval_js("undefined", "old result", base).unwrap(),
            "old result"
        );
    }

    #[test]
    fn next_content_url_options_reach_following_request() {
        use crate::crawler::{analyze_url, HttpSession};
        use crate::model::rule::ContentRule;
        use crate::parser::rule_engine::RuleEngine;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/chapter", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                request.push_str(&line);
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            .unwrap();
            request.to_ascii_lowercase()
        });
        let source = BookSource {
            book_source_url: base.clone(),
            rule_content: Some(ContentRule {
                next_content_url: Some(r#"@js:'/next,{"headers":{"X-Next":"rule"}}'"#.to_owned()),
                ..Default::default()
            }),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let next = RuleEngine::new()
            .unwrap()
            .next_content_url(&source, "<p>first</p>", &base)
            .unwrap();
        assert_eq!(
            next,
            format!(
                "http://{}/next,{{\"headers\":{{\"X-Next\":\"rule\"}}}}",
                base.split('/').nth(2).unwrap()
            )
        );
        let spec = analyze_url(&next, "", 1, &base, &source).unwrap();
        assert_eq!(
            HttpSession::new(&source, 3000)
                .unwrap()
                .fetch(&spec, 1024)
                .unwrap()
                .body,
            "ok"
        );
        let request = server.join().unwrap();
        assert!(request.starts_with("get /next http/1.1"), "{request}");
        assert!(request.contains("x-next: rule\r\n"), "{request}");
    }

    #[test]
    fn java_connect_and_ajax_share_normal_url_header_plan() {
        use crate::crawler::session::{with_active_session, ExecuteSession};
        use crate::crawler::{analyze_url, HttpSession};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..4 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                }
                requests.push(request.to_ascii_lowercase());
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                .unwrap();
            }
            requests
        });
        let source = BookSource {
            book_source_url: base.clone(),
            header: Some(r#"{"X-Source":"source","X-Order":"source"}"#.to_owned()),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let state = ExecuteSession {
            header: Some(serde_json::json!({"X-Login":"login","X-Order":"login"})),
            ..Default::default()
        };
        let rule = r#"/page,{"headers":{"X-Order":"option"},"js":"java.headerMap.put('X-Order','js'); java.headerMap.put('X-Js','signed'); result"}"#;
        let client = HttpClient::standalone();
        let (result, _) = with_active_session(Some(&state), &source.book_source_url, |_| {
            let spec = analyze_url(rule, "", 1, &base, &source).unwrap();
            let normal = HttpSession::new(&source, 3000)
                .unwrap()
                .fetch(&spec, 1024)
                .unwrap()
                .body;
            let target = format!("{base}{rule}");
            let connect = with_js_http_context(&client, &source, || {
                eval_js(
                    &format!(
                        "(() => {{ const body = java.connect({}).body(); return body + '|' + (java.headerMap === undefined); }})()",
                        serde_json::to_string(&target).unwrap()
                    ),
                    "",
                    &base,
                )
                .unwrap()
            });
            let ajax = with_js_http_context(&client, &source, || {
                eval_js(
                    &format!(
                        "(() => {{ const body = java.ajax({}); return body + '|' + (java.headerMap === undefined); }})()",
                        serde_json::to_string(&target).unwrap()
                    ),
                    "",
                    &base,
                )
                .unwrap()
            });
            let explicit = with_js_http_context(&client, &source, || {
                eval_js(
                    &format!(
                        "(() => {{ const body = java.connect({}, {{'X-Explicit':'yes','X-Order':'passed'}}).body(); return body + '|' + (java.headerMap === undefined); }})()",
                        serde_json::to_string(&target).unwrap()
                    ),
                    "",
                    &base,
                )
                .unwrap()
            });
            (normal, connect, ajax, explicit)
        });
        assert_eq!(
            result,
            (
                "ok".into(),
                "ok|true".into(),
                "ok|true".into(),
                "ok|true".into()
            )
        );
        let requests = server.join().unwrap();
        for request in &requests[..3] {
            assert!(request.contains("x-source: source\r\n"), "{request}");
            assert!(request.contains("x-login: login\r\n"), "{request}");
            assert!(request.contains("x-order: js\r\n"), "{request}");
            assert!(request.contains("x-js: signed\r\n"), "{request}");
        }
        let explicit = &requests[3];
        assert!(!explicit.contains("x-source:"), "{explicit}");
        assert!(!explicit.contains("x-login:"), "{explicit}");
        assert!(explicit.contains("x-explicit: yes\r\n"), "{explicit}");
        assert!(explicit.contains("x-order: js\r\n"), "{explicit}");
        assert!(explicit.contains("x-js: signed\r\n"), "{explicit}");
    }

    #[test]
    fn nested_connect_restores_outer_scope_and_header_map_after_failure() {
        let source = BookSource {
            book_source_url: "https://example.com".to_owned(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let mut headers = vec![("X-Outer".to_owned(), "before".to_owned())];
        let result = with_js_http_context(&client, &source, || {
            eval_js_url_with_headers(
                r#"globalThis.outerMarker=1;
java.outerMarker=1;
java.headerMap.put('X-Outer','after');
java.connect('ftp://invalid,{"js":"var leakedVar=1; globalThis.leakedGlobal=1; java.leakedJava=1; globalThis.outerMarker=2; java.outerMarker=2; throw 123"}');
[globalThis.outerMarker, typeof leakedVar, typeof globalThis.leakedGlobal, java.outerMarker, typeof java.leakedJava, java.headerMap.get('X-Outer')].join('|')"#,
                "https://example.com", "", 1, &source.book_source_url,
                &source.book_source_url, None, &mut headers,
            ).unwrap()
        });
        assert_eq!(result, "1|undefined|undefined|1|undefined|after");
        assert_eq!(headers, vec![("X-Outer".to_owned(), "after".to_owned())]);
    }

    #[test]
    fn p2_str_response_defaults_and_json_roundtrip_preserve_new_fields() {
        let result = eval_js(r#"
            const legacy = __readerMakeStrResponse({body: 'legacy', code: 201});
            const restored = __readerMakeStrResponse(JSON.stringify(legacy));
            const timed = __readerMakeStrResponse({body: 'timed', code: 200, callTime: 37, errorBody: null});
            const timedCopy = __readerMakeStrResponse(JSON.stringify(timed));
            [legacy.callTime(), legacy.errorBody() === null, restored.callTime(),
                restored.body(), timedCopy.callTime(), timedCopy.errorBody() === null,
                timedCopy.raw().body().string(), JSON.parse(JSON.stringify(timed)).callTime].join('|')
        "#, "", "https://example.test").unwrap();
        assert_eq!(result, "0|true|0|legacy|37|true|timed|37");
    }

    #[test]
    fn p2_str_response_measures_success_and_http_errors_without_error_body() {
        for analyzed in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/timed", listener.local_addr().unwrap());
            let server = thread::spawn(move || {
                for status in [200, 404, 503] {
                    let (mut stream, _) = accept_with_timeout(&listener);
                    let mut request = [0; 2048];
                    stream.read(&mut request).unwrap();
                    thread::sleep(Duration::from_millis(50));
                    write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody").unwrap();
                }
            });
            let source = BookSource {
                book_source_url: url.clone(),
                ..Default::default()
            };
            let client = HttpClient::standalone();
            let script = format!(
                r#"
                JSON.stringify([200,404,503].map(status => {{
                    const response = java.connect({url:?});
                    const copy = __readerMakeStrResponse(JSON.stringify(response));
                    return [response.code(), response.body(), response.raw().body().string(),
                        Number.isInteger(response.callTime()) && response.callTime() >= 30 && response.callTime() < 2000,
                        response.errorBody() === null, copy.callTime() === response.callTime(),
                        response.isSuccessful() === (status === 200)];
                }}))
            "#
            );
            let run = || eval_js(&script, "", &url).unwrap();
            let result = if analyzed {
                with_js_http_context(&client, &source, run)
            } else {
                with_js_http_client(&client, run)
            };
            server.join().unwrap();
            assert_eq!(
                serde_json::from_str::<JsonValue>(&result).unwrap(),
                json!([
                    [200, "body", "body", true, true, true, true],
                    [404, "body", "body", true, true, true, true],
                    [503, "body", "body", true, true, true, true]
                ]),
                "analyzed={analyzed}"
            );
        }
    }

    #[test]
    fn p2_str_response_time_includes_body_js_and_keeps_failure_defaults() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/timed", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for (status, delay) in [(404, 30), (200, 50), (404, 30)] {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut request = [0; 2048];
                stream.read(&mut request).unwrap();
                thread::sleep(Duration::from_millis(delay));
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                .unwrap();
            }
        });
        let client = HttpClient::standalone();
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let target = format!(
            "{url},{}",
            json!({"bodyJs": format!("java.connect({url:?}).body() + result")})
        );
        let failure = format!(
            "{url},{}",
            json!({"bodyJs": "throw new Error('body-js-failed')"})
        );
        let result = with_js_http_context(&client, &source, || {
            eval_js(&format!(r#"
            const response = java.connect({target:?});
            const failed = java.connect({failure:?});
            const typed = java.connect('data:;base64,bG9jYWw=,{{"type":"chapter"}}');
            [response.code(), response.body(), response.callTime() >= 60 && response.callTime() < 2000,
                response.errorBody() === null, failed.callTime(), failed.errorBody() === null,
                failed.body().includes('body-js-failed'), failed.code(),
                typed.callTime(), typed.body()].join('|')
        "#), "", &url).unwrap()
        });
        server.join().unwrap();
        assert_eq!(result, "404|okok|true|true|0|true|true|200|0|6c6f63616c");
    }

    #[test]
    fn p2_str_response_call_time_includes_business_retries() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/retry", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for status in [503, 200] {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut request = [0; 2048];
                stream.read(&mut request).unwrap();
                thread::sleep(Duration::from_millis(75));
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                .unwrap();
            }
        });
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let target = format!("{url},{}", json!({"retry": 1}));
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(
                &format!(
                    "const r = java.connect({target:?}); [r.code(), r.body(), r.callTime() >= 120 && r.callTime() < 2000, r.errorBody() === null].join('|')"
                ),
                "",
                &url,
            )
            .unwrap()
        });
        server.join().unwrap();
        assert_eq!(result, "200|ok|true|true");
    }

    #[test]
    fn p2_str_response_call_time_excludes_url_rule_initialization() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/init", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut request = [0; 2048];
            stream.read(&mut request).unwrap();
            thread::sleep(Duration::from_millis(20));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let target = format!(
            "{url},{}",
            json!({"js": "const started = Date.now(); while (Date.now() - started < 120) {} result"})
        );
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(
                &format!(
                    "const started = Date.now(); const r = java.connect({target:?}); const elapsed = Date.now() - started; [r.code(), r.body(), elapsed - r.callTime() >= 80, r.callTime() >= 10 && r.callTime() < 2000].join('|')"
                ),
                "",
                &url,
            )
            .unwrap()
        });
        server.join().unwrap();
        assert_eq!(result, "200|ok|true|true");
    }

    #[test]
    fn p2_str_response_transport_timeout_and_ajax_all_keep_zero_defaults() {
        for analyzed in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/timeout", listener.local_addr().unwrap());
            let server = thread::spawn(move || {
                for delay in [100, 50] {
                    let (mut stream, _) = accept_with_timeout(&listener);
                    let mut request = [0; 2048];
                    stream.read(&mut request).unwrap();
                    thread::sleep(Duration::from_millis(delay));
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                }
            });
            let client = HttpClient::standalone();
            let source = BookSource {
                book_source_url: url.clone(),
                ..Default::default()
            };
            let script = format!(
                r#"
                const failed = java.connect({url:?}, {{}}, 20);
                const all = java.ajaxAll(['ftp://invalid', {url:?}]);
                [failed.callTime(), failed.errorBody() === null, /timeout|timed out/i.test(failed.body()),
                    failed.code(), failed.isSuccessful(), all[0].callTime(), all[0].errorBody() === null,
                    all[1].callTime() >= 30 && all[1].callTime() < 2000, all[1].errorBody() === null,
                    all[1].body()].join('|')
            "#
            );
            let run = || eval_js(&script, "", &url).unwrap();
            let result = if analyzed {
                with_js_http_context(&client, &source, run)
            } else {
                with_js_http_client(&client, run)
            };
            server.join().unwrap();
            assert_eq!(result, "0|true|true|200|true|0|true|true|true|ok");
        }
    }

    #[test]
    fn p2_simple_timeout_validates_parameters_and_preserves_variable_get() {
        let result = eval_js(r#"
            const calls = [];
            const response = (method, timeout) => {
                calls.push([method, timeout]); return JSON.stringify({body: 'ok', code: 200});
            };
            java.__nativeGet = (_, headers, timeout) => response('GET', timeout);
            java.__nativeHead = (_, headers, timeout) => response('HEAD', timeout);
            java.__nativePost = (_, body, headers, timeout) => response('POST', timeout);
            const invoke = timeout => [java.get('http://example.test', {}, timeout),
                java.head('http://example.test', {}, timeout), java.post('http://example.test', 'body', {}, timeout)];
            for (const timeout of [undefined, null, 1, 120000]) {
                if (!invoke(timeout).every(item => item.body() === 'ok' && item.statusCode() === 200)) throw new Error('valid timeout failed');
            }
            let rejected = 0;
            for (const timeout of [0, -1, 120001, 0.5, NaN, Infinity, -Infinity, '20', {}, [], true]) {
                for (const call of [() => java.get('http://example.test', {}, timeout),
                    () => java.head('http://example.test', {}, timeout), () => java.post('http://example.test', 'body', {}, timeout)]) {
                    try { call(); } catch (error) { if (error instanceof TypeError) rejected++; }
                }
            }
            java.put('p2-simple-token', 'retained');
            JSON.stringify([calls.map(call => call[1]), rejected, java.get('p2-simple-token')])
        "#, "", "https://example.test").unwrap();
        assert_eq!(
            result,
            r#"[[null,null,null,null,null,null,1,1,1,120000,120000,120000],33,"retained"]"#
        );
    }

    #[test]
    fn p2_simple_timeout_bounds_io_and_does_not_leak_into_defaults() {
        for method in ["GET", "HEAD", "POST"] {
            for slow_body in [false, true] {
                if method == "HEAD" && slow_body {
                    continue;
                }
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let url = format!("http://{}/simple", listener.local_addr().unwrap());
                let server = thread::spawn(move || {
                    let mut requests = Vec::new();
                    for delay in [150, 70] {
                        let (mut stream, _) = accept_with_timeout(&listener);
                        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                        let mut request = String::new();
                        let mut length = 0;
                        loop {
                            let mut line = String::new();
                            reader.read_line(&mut line).unwrap();
                            if line == "\r\n" || line.is_empty() {
                                break;
                            }
                            if let Some(value) =
                                line.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                length = value.trim().parse::<usize>().unwrap();
                            }
                            request.push_str(&line);
                        }
                        let mut body = vec![0; length];
                        reader.read_exact(&mut body).unwrap();
                        request.push_str(&String::from_utf8(body).unwrap());
                        requests.push(request.to_ascii_lowercase());
                        if slow_body {
                            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n").unwrap();
                        }
                        thread::sleep(Duration::from_millis(delay));
                        let body = if method == "HEAD" { "" } else { "ok" };
                        let response = if slow_body {
                            body.to_string()
                        } else {
                            format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{body}")
                        };
                        let _ = stream.write_all(response.as_bytes());
                    }
                    requests
                });
                let call = |timeout: &str| match method {
                    "POST" => {
                        format!("java.post({url:?}, 'bid=42', {{'X-Test':'kept'}}, {timeout})")
                    }
                    "HEAD" => format!("java.head({url:?}, {{'X-Test':'kept'}}, {timeout})"),
                    _ => format!("java.get({url:?}, {{'X-Test':'kept'}}, {timeout})"),
                };
                let script = format!("const started = Date.now(); const failed = {}; const elapsed = Date.now() - started; const ok = {}; [failed.statusCode() === 0, /timeout|timed out/i.test(failed.body()), elapsed < 1000, ok.statusCode(), ok.body()].join('|')", call("30"), call("null"));
                let client = HttpClient::new(1000, None, None).unwrap();
                let result = with_js_http_client(&client, || eval_js(&script, "", &url).unwrap());
                assert_eq!(
                    result,
                    if method == "HEAD" {
                        "true|true|true|200|"
                    } else {
                        "true|true|true|200|ok"
                    },
                    "method={method} slow_body={slow_body}"
                );
                let requests = server.join().unwrap();
                assert!(requests.iter().all(|request| request
                    .starts_with(&format!("{} /simple ", method.to_ascii_lowercase()))
                    && request.contains("x-test: kept")));
                if method == "POST" {
                    assert!(requests.iter().all(|request| request.ends_with("bid=42")
                        && request.contains("content-type: application/x-www-form-urlencoded")));
                }
            }
        }
    }

    #[test]
    fn p2_simple_timeout_extends_default_without_following_redirects() {
        for method in ["GET", "HEAD", "POST"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/redirect", listener.local_addr().unwrap());
            let server = thread::spawn(move || {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(100));
                stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            });
            let client = HttpClient::new(30, None, None).unwrap();
            let call = match method {
                "POST" => format!("java.post({url:?}, '', {{}}, 500)"),
                "HEAD" => format!("java.head({url:?}, {{}}, 500)"),
                _ => format!("java.get({url:?}, {{}}, 500)"),
            };
            let source = BookSource {
                book_source_url: url.clone(),
                ..Default::default()
            };
            let result = with_js_http_context(&client, &source, || {
                eval_js(
                &format!("const response = {call}; [response.statusCode(), response.header('location'), response.url()].join('|')"), "", &url).unwrap()
            });
            server.join().unwrap();
            assert_eq!(result, format!("302|/final|{url}"), "method={method}");
        }
    }

    #[test]
    fn simple_http_methods_forward_optional_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..5 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                }
                requests.push(request.to_ascii_lowercase());
                let request = &requests[requests.len() - 1];
                let is_head = request.starts_with("head ");
                let response_body = if is_head { "" } else { "ok" };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                )
                .unwrap();
            }
            requests
        });

        let url = format!("http://{address}/api");
        let client = HttpClient::standalone();
        let source = BookSource {
            book_source_url: url.clone(),
            header: Some(r#"{"X-Source":"not-for-simple-helpers"}"#.to_owned()),
            ..Default::default()
        };
        let result = with_js_http_context(&client, &source, || {
            eval_js(
                &format!(
                    "(() => {{ const get = java.get('{url}', {{'X-Test':'get'}}); const post = java.post('{url}', 'body', {{'X-Test':'post'}}); const head = java.head('{url}', {{'X-Test':'head'}}); java.post('{url}', 'bid=42', {{}}); java.post('{url}', '{{}}', {{'content-type':'application/json'}}); return [get.body(), get.statusCode(), post.body(), head.statusCode(), String(get), head.body(), get.headers().get('content-length')].join('|'); }})()"
                ),
                "",
                &url,
            )
            .unwrap()
        });
        assert_eq!(result, "ok|200|ok|200|ok||2");

        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("get /api "));
        assert!(requests[0].contains("x-test: get"));
        assert!(requests
            .iter()
            .all(|request| !request.contains("x-source:")));
        assert!(requests[1].starts_with("post /api "));
        assert!(requests[1].contains("x-test: post"));
        assert!(requests[1].contains("content-type: application/x-www-form-urlencoded"));
        assert!(requests[2].starts_with("head /api "));
        assert!(requests[2].contains("x-test: head"));
        assert!(requests[3].contains("content-type: application/x-www-form-urlencoded"));
        assert!(requests[4].contains("content-type: application/json"));
        assert!(!requests[4].contains("application/x-www-form-urlencoded"));
    }

    #[test]
    fn nashorn_java_importer_decrypts_aes_payload() {
        let key = "242ccb8230d709e1";
        let iv = "0123456789abcdef";
        let plaintext = "本地解析正文测试";
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(java_aes_base64_encode(
                plaintext,
                key,
                "AES/CBC/PKCS5Padding",
                iv,
            ))
            .unwrap();
        let mut payload = iv.as_bytes().to_vec();
        payload.extend(encrypted);
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        let script = format!(
            r#"
                var javaImport = new JavaImporter();
                javaImport.importPackage(Packages.java.lang, Packages.javax.crypto.spec,
                    Packages.javax.crypto, Packages.java.util);
                with (javaImport) {{
                    function decode(content) {{
                        var ivEncData = Base64.getDecoder().decode(String(content));
                        var key = SecretKeySpec(String("{key}").getBytes(), "AES");
                        var iv = IvParameterSpec(Arrays.copyOfRange(ivEncData, 0, 16));
                        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(2, key, iv);
                        return String(cipher.doFinal(Arrays.copyOfRange(ivEncData, 16, ivEncData.length)));
                    }}
                }}
                decode("{encoded}");
            "#
        );
        assert_eq!(
            eval_js(&script, "", "https://example.com").unwrap(),
            plaintext
        );
    }

    #[test]
    fn java_importer_supports_legado_hmac_sha1_fixture() {
        let script = r#"
            var aly = new JavaImporter(
                Packages.javax.crypto.Mac,
                Packages.javax.crypto.spec.SecretKeySpec,
                Packages.javax.xml.bind.DatatypeConverter,
                Packages.java.net.URLEncoder,
                Packages.java.lang.String,
                Packages.android.util.Base64
            );
            with (aly) {
                function percentEncode(value) {
                    return URLEncoder.encode(value, "UTF-8")
                        .replace("+", "%20")
                        .replace("*", "%2A")
                        .replace("%7E", "~");
                }
                function sign(stringToSign, accessKeySecret) {
                    var mac = Mac.getInstance("HmacSHA1");
                    mac.init(new SecretKeySpec(
                        String(accessKeySecret + "&").getBytes("UTF-8"), "HmacSHA1"));
                    var signData = mac.doFinal(String(stringToSign).getBytes("UTF-8"));
                    var signBase64 = Base64.encodeToString(signData, Base64.NO_WRAP);
                    return percentEncode(signBase64);
                }
            }
            sign("reader", "secret");
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "%2BziHIM45rqfvezm%2F4BidN45XHvo%3D"
        );
    }

    #[test]
    fn base64_shims_preserve_byte_array_semantics() {
        let script = r#"
            const bytes = [97, 98, 99];
            const standard = android.util.Base64.encodeToString(
                bytes, android.util.Base64.NO_WRAP);
            const decoded = java.util.Base64.getDecoder().decode(standard).join(',');
            const urlSafe = java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString([251, 255]);
            const long = Array.from({length: 60}, (_, i) => i);
            const wrapped = android.util.Base64.encodeToString(
                long, android.util.Base64.DEFAULT);
            const crlf = android.util.Base64.encodeToString(
                long, android.util.Base64.CRLF);
            [
                standard,
                decoded,
                urlSafe,
                wrapped.includes('\n'),
                wrapped.endsWith('\n'),
                crlf.includes('\r\n'),
                crlf.endsWith('\r\n')
            ].join('|');
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "YWJj|97,98,99|-_8|true|true|true|true"
        );
    }

    #[test]
    fn legado_android_compat_shims_use_session_and_safe_host_objects() {
        let initial = ExecuteSession::default();
        let script = r#"
            const preferences = context.getSharedPreferences('reader', context.MODE_PRIVATE);
            preferences.edit().putString('token', 'saved').apply();
            preferences.edit().putString('temporary', 'remove').commit();
            preferences.edit().remove('temporary').apply();
            const encoded = URLEncoder.encode('reader rust');
            const decoded = URLDecoder.decode(encoded);
            const base64 = java.util.Base64.getEncoder().encodeToString('reader');
            const decodedBase64 = java.bytesToStr(
                android.util.Base64.decode(base64, android.util.Base64.DEFAULT), 'UTF-8');
            const uuid = UUID.randomUUID().toString();
            const javaUuid = java.util.UUID.randomUUID().toString();
            const helperUuid = java.randomUUID();
            if (preferences.getString('token', '') !== 'saved' ||
                preferences.getString('temporary', 'fallback') !== 'fallback' ||
                decoded !== 'reader rust' || decodedBase64 !== 'reader' ||
                uuid.length !== 36 || javaUuid.length !== 36 || helperUuid.length !== 36 ||
                System.currentTimeMillis() <= 0 ||
                !application || !context || !activity || !app ||
                !android.util.Log || Log.d('compat', 'ok') !== 0) {
                throw new Error('compatibility shim failed');
            }
            'OK'
        "#;
        let (result, delta) = with_active_session(Some(&initial), "https://example.com", |_| {
            eval_js(script, "", "https://example.com").unwrap()
        });
        assert_eq!(result, "OK");
        assert_eq!(
            delta.unwrap().variables.unwrap()["__prefs:reader:token"],
            JsonValue::String("saved".to_string())
        );
    }

    #[test]
    fn compat_jsoup_subset_supports_select_collection_and_element_methods() {
        let script = r#"
            var doc = org.jsoup.Jsoup.parse(result);
            var items = doc.select('ul.volume-chapters li.chapter-li:not(.volume-cover)');
            var output = [];
            for (var i = 0; i < items.size(); i++) {
                var item = items.get(i);
                var link = item.select('a').first();
                output.push({
                    title: link ? link.text() : '',
                    url: link ? link.attr('href') : '',
                    isVolume: item.hasClass('chapter-bar')
                });
            }
            JSON.stringify(output);
        "#;
        let body = r#"<ul class="volume-chapters">
            <li class="chapter-li"><a href="/chapter/1">Chapter 1</a></li>
            <li class="chapter-li chapter-bar"><a href="/volume/1">Volume 1</a></li>
            <li class="chapter-li volume-cover"><a href="/cover">Cover</a></li>
        </ul>"#;

        let output = eval_js(script, body, "https://source.example").unwrap();
        let items = serde_json::from_str::<Vec<JsonValue>>(&output).unwrap();

        assert_eq!(items.len(), 2, "Jsoup output: {output}");
        assert_eq!(items[0]["title"], "Chapter 1");
        assert_eq!(items[0]["url"], "/chapter/1");
        assert_eq!(items[0]["isVolume"], false);
        assert_eq!(items[1]["isVolume"], true);
    }

    #[test]
    fn toc_refresh_shims_are_rejected_outside_pre_update_context() {
        assert!(eval_js("java.reGetBook()", "", "https://example.com").is_err());
        assert!(eval_js("java.refreshTocUrl()", "", "https://example.com").is_err());
    }

    #[test]
    fn compat_cookie_get_key_reads_session_cookie_values() {
        let initial = ExecuteSession {
            cookies: Some("sid=initial_token; token=a=b=c".to_string()),
            ..Default::default()
        };
        let result = with_active_session(Some(&initial), "https://example.com", |_| {
            eval_js(
                "[cookie.getKey('example.com', 'sid'), cookie.getKey('https://example.com/path', 'token'), cookie.getKey('example.com', 'missing')].join('|')",
                "",
                "https://example.com",
            )
            .unwrap()
        })
        .0;

        assert_eq!(result, "initial_token|a=b=c|");
    }

    #[test]
    fn java_get_cookie_matches_legado_overloads_and_session_scope() {
        let url = "https://example.com";
        let initial = ExecuteSession {
            cookies: Some("sid=initial_token; token=a=b=c".to_string()),
            ..Default::default()
        };
        let (result, _) = with_active_session(Some(&initial), url, |active| {
            let before = active.current_session();
            let result = eval_js(
                r#"[
                    typeof java.getCookie('example.com') === 'string',
                    java.getCookie('example.com') === cookie.getCookie('example.com'),
                    java.getCookie('example.com', null) === cookie.getCookie('example.com'),
                    java.getCookie('example.com', undefined) === cookie.getCookie('example.com'),
                    java.getCookie('example.com', 'sid'),
                    java.getCookie('https://example.com/path', 'token'),
                    java.getCookie('example.com', 'missing'),
                    java.getCookie('example.com', ''),
                    java.getCookie('https://unrelated.example', 'sid')
                ].join('|')"#,
                "",
                url,
            )
            .unwrap();
            assert_eq!(
                active.current_session(),
                before,
                "Cookie reads must not change session state"
            );
            result
        });
        assert_eq!(result, "true|true|true|true|initial_token|a=b=c|||");
        let (result, _) = with_active_session(None, url, |_| {
            eval_js("java.getCookie('example.com', 'sid')", "", url).unwrap()
        });
        assert_eq!(result, "");
        assert_eq!(
            eval_js("java.getCookie('example.com')", "", url).unwrap(),
            ""
        );
        assert!(eval_js("java.getCookie()", "", url).is_err());
        assert!(eval_js("java.getCookie('example.com', {})", "", url).is_err());
    }

    #[test]
    fn compat_cookie_replace_merges_existing_values() {
        let initial = ExecuteSession {
            cookies: Some("sid=old; keep=yes".to_string()),
            ..Default::default()
        };
        let (result, _) = with_active_session(Some(&initial), "https://example.com", |_| {
            eval_js(
                "cookie.replaceCookie('https://example.com/path', 'sid=new; added=1'); [cookie.getKey('example.com','sid'), cookie.getKey('example.com','keep'), cookie.getKey('example.com','added')].join('|')",
                "",
                "https://example.com",
            )
            .unwrap()
        });

        assert_eq!(result, "new|yes|1");
    }

    #[test]
    fn compat_java_set_content_and_get_elements_support_json_and_html() {
        let script = r#"
            java.setContent(JSON.stringify({data:{list:[{name:'first'},{name:'last'}]}}));
            const list = java.getElements('$.data.list[*]').toArray();
            const all = java.getElement('$.data.list[*]');
            const last = java.getElement('$.data.list[-1]');
            const firstName = java.getString('$.data.list[0].name');
            java.setContent('<div><p id="p1"><b>one</b></p><p id="p2">two</p></div>');
            const paragraphs = java.getElements('@@tag.p').toArray();
            [list[0].name, all.length, all[1].name, last.name, firstName,
             paragraphs[0].attr('id'), paragraphs[0].html(), paragraphs[0].text()].join('|')
        "#;
        let result = eval_js(script, "", "https://example.com").unwrap();
        assert_eq!(result, "first|2|last|last|first|p1|<b>one</b>|one");
    }

    #[test]
    fn jsoup_text_supports_java_string_is_empty() {
        let script = r#"
            java.setContent('<div id="list-chapterAll"><dl><dd><a href="/a"></a></dd><dd><a href="/b">Chapter</a></dd></dl></div>');
            const links = java.getElements('#list-chapterAll dl dd a');
            [links.size(), links.get(0).text().isEmpty(),
             links.get(1).text().isEmpty(), ''.isEmpty(),
             'text'.isEmpty(), Object.prototype.propertyIsEnumerable.call(String.prototype, 'isEmpty')].join('|')
        "#;
        assert_eq!(
            eval_js(script, "", "https://fixture.test").unwrap(),
            "2|true|false|true|false|false"
        );
    }

    #[test]
    fn java_get_elements_html_text_setter_updates_serialized_carrier() {
        let script = r#"
            java.setContent('<div id="list-chapterAll"><dl><dd><a href="/one"></a></dd></dl></div>');
            const item = java.getElements('#list-chapterAll dl dd a').first();
            const initial = item.text();
            const ret = item.text('第1章 & 下一章');
            const carrier = JSON.parse(JSON.stringify(item));
            [initial, ret === item, item.text(), item.html(),
             carrier.__readerHtmlElement, carrier.text, carrier.outerHtml,
             item.attr('href')].join('|')
        "#;
        assert_eq!(
            eval_js(script, "", "https://fixture.test").unwrap(),
            "|true|第1章 & 下一章|第1章 &amp; 下一章|true|第1章 & 下一章|<a href=\"/one\">第1章 &amp; 下一章</a>|/one",
        );
    }

    #[test]
    fn jsoup_parsed_elements_expose_tag_name_for_source_rules() {
        let output = eval_js(
            r#"const doc = org.jsoup.Jsoup.parse('<div class="media"><h4>Book</h4></div>');
               const parsed = doc.select('div.media').first();
               const direct = java.getElements('div.media', '<div class="media"></div>').first();
               [parsed.tagName(), direct.tagName()].join('|')"#,
            "",
            "https://fixture.test",
        )
        .unwrap();
        assert_eq!(output, "div|div");
    }

    #[test]
    fn jsoup_constructed_elements_support_source_book_cards() {
        let output = eval_js(
            r#"const div = new org.jsoup.nodes.Element('div');
               const h3 = new org.jsoup.nodes.Element('h3');
               const a = new org.jsoup.nodes.Element('a');
               a.attr('href', '/ciwei/1_2/').text('Book & One');
               h3.appendChild(a);
               div.appendChild(h3);
               const parsed = org.jsoup.Jsoup.parse(div.outerHtml());
               const cards = new org.jsoup.select.Elements();
               cards.add(div);
               const carrier = JSON.parse(JSON.stringify(cards))[0];
               [parsed.select('h3 a').first().text(),
                parsed.select('h3 a').first().attr('href'),
                carrier.__readerHtmlElement, carrier.outerHtml.includes('Book &amp; One')].join('|')"#,
            "",
            "https://fixture.test",
        )
        .unwrap();
        assert_eq!(output, "Book & One|/ciwei/1_2/|true|true");
    }

    #[test]
    fn java_get_string_css_prefix_matches_plain_rules() {
        let script = r#"
            java.setContent('<a href="https://fixture.invalid/book.txt">第一下载地址(首选)</a>');
            [java.getString('@@text.第一下载地址(首选)@href'),
             java.getString('text.第一下载地址(首选)@href'),
             java.getStringList('@@a@href').join('|'),
             java.getString('@@a@href')].join('|')
        "#;
        let result = eval_js(script, "", "https://fixture.invalid").unwrap();
        assert_eq!(
            result,
            vec!["https://fixture.invalid/book.txt"; 4].join("|")
        );
    }

    #[test]
    fn java_get_element_empty_indefinite_queries_are_arrays() {
        let result = eval_js(
            r#"java.setContent('{"items":[]}');
               const all = java.getElement('$.items[*]');
               const filtered = java.getElement('$.items[?(@.id == 1)]');
               [Array.isArray(all), all.length, filtered.map(x => x.id).length].join('|')"#,
            "",
            "https://example.com",
        )
        .unwrap();
        assert_eq!(result, "true|0|0");
    }

    #[test]
    fn real_source_get_string_json_fallback_values_and_blank_url() {
        let body = r#"{"data":{"list":[{"publish_sn":"first"},{"publish_sn":"last"}]},"fallback":"备用","path":"/next","count":0,"enabled":false,"blank":""}"#;
        let result = eval_js(
            r#"[
                java.getString('$.data.list[-1].publish_sn'),
                java.getString('$.missing||$.fallback'),
                java.getString('$.count'),
                java.getString('$.enabled'),
                java.getString('$.missing'),
                java.getString('$.missing', null, true),
                java.getString('$.blank', null, true),
                java.getString('$.missing||$.path', null, true),
                java.getString('$.missing||$.absent', null, true),
                java.getString('$.fallback', '', true),
                java.getString('', null, true)
            ].join('|')"#,
            body,
            "https://example.com/chapter/",
        )
        .unwrap();
        assert_eq!(
            result,
            "last|备用|0|false||https://example.com/chapter/|https://example.com/chapter/|https://example.com/next|https://example.com/chapter/|https://example.com/chapter/|"
        );
    }

    #[test]
    fn analyze_rule_overloads_and_base64_public_api_match_legado_shapes() {
        let script = r#"
            const twoArg = java.getString('$.value', false);
            const blankList = java.getStringList('') === null;
            const chained = java
                .setContent('{"path":"/next"}', 'https://new.example/base/')
                .getString('$.path', undefined, true);
            const bytes = java.base64DecodeToByteArray('YWJj').join(',');
            const flagsDecode = java.base64Decode('YWJj', 0);
            const flagsEncode = java.base64Encode('abc', 2);
            [twoArg, blankList, chained, bytes, flagsDecode, flagsEncode].join('|')
        "#;
        let result = eval_js(script, r#"{"value":"ok"}"#, "https://example.com/old/").unwrap();
        assert_eq!(result, "ok|true|https://new.example/next|97,98,99|abc|YWJj");
    }

    #[test]
    fn source_exposes_url_and_raw_header_in_execute_context() {
        let source = BookSource {
            book_source_url: "https://source.example".to_string(),
            header: Some(r#"{"User-Agent":"reader"}"#.to_string()),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(
                "[source.bookSourceUrl, JSON.parse(source.header)['User-Agent'], source.getKey()].join('|')",
                "",
                &source.book_source_url,
            )
            .unwrap()
        });
        assert_eq!(
            result,
            "https://source.example|reader|https://source.example"
        );
    }

    #[test]
    fn p1_entity_getters_read_live_fields_and_java_kind_list() {
        let bindings = HashMap::from([
            (
                "book".to_string(),
                json!({
                    "name": "Book", "author": "Author", "bookUrl": "book-url",
                    "coverUrl": null, "customCoverUrl": "custom",
                    "wordCount": " 12万 ", "kind": " 玄幻, ,奇幻\n冒险,玄幻 "
                }),
            ),
            (
                "chapter".to_string(),
                json!({"url": "chapter-url", "title": "Chapter", "index": 0}),
            ),
        ]);
        let script = r#"
            const kinds = book.getKindList();
            const initial = [book.getName(), book.getAuthor(), book.getBookUrl(),
                book.getCoverUrl(), book.getDisplayCover(), chapter.getUrl(),
                chapter.getTitle(), chapter.getIndex(), kinds.size(), kinds.get(0),
                Array.from(kinds), book.getKind(), book.getWordCount()];
            book.name = 'Updated'; book.coverUrl = ''; book.customCoverUrl = '';
            chapter.index = 7; chapter.title = 'New';
            book.kind = null; book.wordCount = '  ';
            JSON.stringify([initial, book.getName(), book.getCoverUrl(), book.getDisplayCover(),
                chapter.getIndex(), chapter.getTitle(), book.getKindList().size()])
        "#;
        let result = eval_js_with_bindings(script, "", "https://example.com", &bindings).unwrap();
        assert_eq!(
            serde_json::from_str::<JsonValue>(&result).unwrap(),
            json!([
                [
                    "Book",
                    "Author",
                    "book-url",
                    null,
                    "custom",
                    "chapter-url",
                    "Chapter",
                    0,
                    5,
                    " 12万 ",
                    [" 12万 ", "玄幻", "奇幻", "冒险", "玄幻"],
                    " 玄幻, ,奇幻\n冒险,玄幻 ",
                    " 12万 "
                ],
                "Updated",
                "",
                "",
                7,
                "New",
                0
            ])
        );
        // A new QuickJS Context must see the original bindings, not mutated fields.
        assert_eq!(
            eval_js_with_bindings(
                "book.getName() + '|' + chapter.getIndex()",
                "",
                "https://example.com",
                &bindings
            )
            .unwrap(),
            "Book|0"
        );
    }

    #[test]
    fn p1_entity_getters_preserve_absent_and_null_bindings() {
        assert_eq!(
            eval_js(
                "book.getName() === undefined && chapter.getIndex() === undefined",
                "",
                "https://example.com"
            )
            .unwrap(),
            "true"
        );
        let unicode = HashMap::from([(
            "book".to_string(),
            json!({"wordCount": "\u{FEFF}", "kind": "\u{001c}玄幻\u{001f},\u{FEFF}"}),
        )]);
        assert_eq!(
            eval_js_with_bindings(
                "JSON.stringify(Array.from(book.getKindList()))",
                "",
                "https://example.com",
                &unicode
            )
            .unwrap(),
            "[\"\u{FEFF}\",\"玄幻\",\"\u{FEFF}\"]"
        );
        for value in [JsonValue::Null, json!({})] {
            let bindings = HashMap::from([
                ("book".to_string(), value.clone()),
                ("chapter".to_string(), value.clone()),
            ]);
            let script = if value.is_null() {
                "book === null && chapter === null"
            } else {
                "book.getCoverUrl() === undefined && chapter.getIndex() === undefined && book.getKindList().size() === 0"
            };
            assert_eq!(
                eval_js_with_bindings(script, "", "https://example.com", &bindings).unwrap(),
                "true"
            );
        }
    }

    #[test]
    fn p1_source_put_variable_deletes_single_value_without_removing_keyed_values() {
        let source = BookSource {
            book_source_url: "https://p1-source.example".to_string(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let initial = ExecuteSession {
            variables: Some(HashMap::from([
                ("sourceVariable".to_string(), json!("initial")),
                ("keyed".to_string(), json!("retained")),
            ])),
            ..Default::default()
        };
        for (script, expected) in [
            ("source.putVariable(null)", None),
            ("source.putVariable('')", Some(json!(""))),
        ] {
            let (_, delta) = with_active_session(Some(&initial), &source.book_source_url, |_| {
                with_js_http_context(&client, &source, || {
                    eval_js(script, "", &source.book_source_url).unwrap()
                })
            });
            let variables = delta.unwrap().variables.unwrap();
            assert_eq!(variables.get("sourceVariable"), expected.as_ref());
            assert_eq!(variables.get("keyed"), Some(&json!("retained")));
        }
    }

    #[test]
    fn p1_des_decode_aliases_forward_known_vector_and_reject_invalid_input() {
        // OpenSSL DES-CBC/PKCS5: UTF-8 中文reader, key 12345678, iv abcdefgh.
        // Offline host fixture checks the wrapper protocol, not the real Lua DES provider.
        let result = eval_js(r#"
            let calls = 0;
            java.hostCall = (operation, args) => {
                if (operation === 'crypto.capabilities') return {
                    protocol: 1, maxInputBytes: 1024,
                    symmetric: {'DES/CBC/PKCS5PADDING': {keyBytes: [8]}}
                };
                if (operation !== 'crypto.symmetric' || args.action !== 'decrypt'
                    || args.transformation !== 'DES/CBC/PKCS5PADDING'
                    || JSON.stringify(args.key) !== '[49,50,51,52,53,54,55,56]'
                    || JSON.stringify(args.iv) !== '[97,98,99,100,101,102,103,104]') {
                    throw new Error('unexpected DES request');
                }
                if (JSON.stringify(args.data) !== '[10,202,54,28,91,177,252,241,21,163,20,134,45,192,129,27]') {
                    throw new Error('invalid ciphertext');
                }
                calls++;
                return [228,184,173,230,150,135,114,101,97,100,101,114];
            };
            const values = [java.desDecodeToString('Cso2HFux/PEVoxSGLcCBGw==', '12345678', 'DES/CBC/PKCS5Padding', 'abcdefgh'),
                java.desBase64DecodeToString('0aca361c5bb1fcf115a314862dc0811b', '12345678', 'DES/CBC/PKCS5Padding', 'abcdefgh')];
            let rejected = 0;
            for (const [data, key, iv] of [['bad!', '12345678', 'abcdefgh'],
                ['Cso2HFux/PEVoxSGLcCBGw==', 'short', 'abcdefgh'],
                ['Cso2HFux/PEVoxSGLcCBGw==', '12345678', '短']]) {
                try { java.desDecodeToString(data, key, 'DES/CBC/PKCS5Padding', iv); }
                catch (_) { rejected++; }
            }
            JSON.stringify([values, calls, rejected, typeof values[0]])
        "#, "", "https://example.com").unwrap();
        assert_eq!(result, r#"[["中文reader","中文reader"],2,3,"string"]"#);
    }

    #[test]
    fn source_contract_uses_book_source_key_and_single_source_variable() {
        let source = BookSource {
            book_source_url: "https://source.example".to_string(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let initial = ExecuteSession {
            variables: Some(
                [
                    ("sourceVariable".to_string(), json!("initial")),
                    (
                        "userInfo_https://source.example".to_string(),
                        json!("encrypted"),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let (result, delta) = with_active_session(Some(&initial), &source.book_source_url, |_| {
            with_js_http_context(&client, &source, || {
                eval_js(
                    r#"
                            const initialValue = source.getVariable();
                            const setResult = source.setVariable('saved');
                            const saved = source.getVariable();
                            const aliasResult = source.putVariable('alias');
                            if (source.getVariable() !== 'alias' || aliasResult !== undefined) throw new Error('single variable alias failed');
                            source.setVariable('keyed', 'retained');
                            source.putVariable(null);
                            if (source.getVariable() !== '' || source.getVariable('keyed') !== 'retained') throw new Error('alias deletion changed keyed variables');
                            source.putVariable('');
                            if (source.getVariable() !== '') throw new Error('empty source variable failed');
                            const putResult = source.put('token', 'value');
                            const sourceValue = source.get('token');
                            const removeLoginResult = source.removeLoginInfo();
                            source.setVariable(null);
                            [
                                source.getKey(),
                                initialValue,
                                saved,
                                source.getVariable(),
                                putResult,
                                sourceValue,
                                source.getLoginHeader() === null,
                                source.getLoginInfo() === null,
                                typeof setResult === 'undefined',
                                typeof removeLoginResult === 'undefined'
                            ].join('|')
                        "#,
                    "",
                    &source.book_source_url,
                )
                .unwrap()
            })
        });
        assert_eq!(
            result,
            "https://source.example|initial|saved||value|value|true|true|true|true"
        );
        let variables = delta.unwrap().variables.unwrap();
        assert_eq!(
            variables.get("v_https://source.example_token"),
            Some(&json!("value"))
        );
        assert!(!variables.contains_key("userInfo_https://source.example"));
    }

    #[test]
    fn symmetric_crypto_matches_legado_aes_cbc_shapes() {
        let script = r#"
            const cipher = java.createSymmetricCrypto(
                'AES/CBC/PKCS5Padding',
                '1234567890abcdef',
                'abcdef1234567890'
            );
            const encryptedBytes = cipher.encrypt('reader');
            const encryptedBase64 = cipher.encryptBase64('reader');
            const encryptedHex = cipher.encryptHex('reader');
            const decryptedFromBytes = cipher.decryptStr(encryptedBytes);
            const decryptedFromBase64 = cipher.decryptStr(encryptedBase64);
            const decryptedFromHex = cipher.decryptStr(encryptedHex);
            [
                Array.isArray(encryptedBytes),
                encryptedBytes.length > 0,
                decryptedFromBytes,
                decryptedFromBase64,
                decryptedFromHex
            ].join('|')
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "true|true|reader|reader|reader"
        );

        assert_eq!(eval_js(
            "(()=>{const c=java.createSymmetricCrypto('AES/ECB/PKCS5Padding', '1234567890abcdef');return c.decryptStr(c.encrypt('reader'));})()",
            "",
            "https://example.com"
        ).unwrap(), "reader");
        assert!(eval_js(
            "java.createSymmetricCrypto('AES/CBC/PKCS5Padding', 'short', 'abcdef1234567890').encryptBase64('reader')",
            "",
            "https://example.com"
        )
        .is_err());
    }

    #[test]
    fn to_num_chapter_matches_legado_number_normalization() {
        let script = r#"
            [
                java.toNumChapter('第123章'),
                java.toNumChapter('第１２３章'),
                java.toNumChapter('第一二三章'),
                java.toNumChapter('第一百零二章'),
                java.toNumChapter('第十二章'),
                java.toNumChapter('第二十章'),
                java.toNumChapter('第一千二章'),
                java.toNumChapter('前言'),
                java.toNumChapter('第abc章')
            ].join('|')
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "第123章|第123章|第123章|第102章|第12章|第20章|第1200章|前言|第-1章"
        );
    }

    #[test]
    fn webview_renders_supplied_html_and_runs_final_script_after_load() {
        let source = BookSource {
            book_source_url: "https://example.test/".into(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(
                r#"java.webView(
                    '<!doctype html><html><body><script>document.body.innerHTML="<p>page</p>"</script></body></html>',
                    'https://example.test/page',
                    'document.readyState + "|" + document.body.innerHTML'
                )"#,
                "",
                &source.book_source_url,
            )
            .unwrap()
        });
        assert_eq!(result, "complete|<p>page</p>");

        let rendered = with_js_http_context(&client, &source, || {
            eval_js(
                r#"java.webView(
                    '<!doctype html><html><body><script>window.marker=1</script><p>static</p></body></html>',
                    'https://example.test/page',
                    null
                )"#,
                "",
                &source.book_source_url,
            )
            .unwrap()
        });
        assert!(rendered.contains("<script>window.marker=1</script>"));
        assert!(rendered.contains("<p>static</p>"));
    }

    #[test]
    fn webview_url_fetch_uses_browser_client_cookie_jar() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/page");
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut saw_cookie = false;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if line.to_ascii_lowercase().starts_with("cookie:") && line.contains("wv=1") {
                    saw_cookie = true;
                }
            }
            let body = "<!doctype html><html><body><script>document.body.innerHTML='<p>fetched</p>'</script></body></html>";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            saw_cookie
        });

        let source = BookSource {
            book_source_url: format!("http://{address}/"),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let session = crate::crawler::HttpSession::new(&source, 15_000).unwrap();
        let parsed_url = url::Url::parse(&url).unwrap();
        assert!(session
            .webview_client()
            .seed_cookie_header("wv=1", &parsed_url));
        let result =
            with_js_http_clients(session.client(), session.webview_client(), &source, || {
                eval_js(
                    &format!("java.webView('', {url:?}, 'document.body.innerHTML')"),
                    "",
                    &source.book_source_url,
                )
                .unwrap()
            });
        assert_eq!(result, "<p>fetched</p>");
        assert!(server.join().unwrap());
    }

    #[test]
    fn import_script_returns_remote_text_without_auto_eval() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let body = "globalThis.__importedValue = 42;";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let source = BookSource {
            book_source_url: format!("http://{address}/"),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let url = format!("http://{address}/script.js");
        let script = format!(
            "(() => {{ const imported = java.importScript('{}'); const before = typeof globalThis.__importedValue; eval(String(imported)); return [before, globalThis.__importedValue, imported.includes('__importedValue')].join('|'); }})()",
            url
        );
        let result = with_js_http_context(&client, &source, || {
            eval_js(&script, "", &source.book_source_url).unwrap()
        });
        assert_eq!(result, "undefined|42|true");
        server.join().unwrap();

        assert!(with_js_http_context(&client, &source, || {
            eval_js(
                "java.importScript('./local.js')",
                "",
                &source.book_source_url,
            )
        })
        .is_err());
    }

    #[test]
    fn cookie_map_to_cookie_converts_maps_without_changing_cookie_store() {
        let input = r#"[
            cookie.mapToCookie(null) === null,
            cookie.mapToCookie(new Map()) === null,
            cookie.mapToCookie(new Map([['sid','a=b'], ['token','new']])) === 'sid=a=b; token=new',
            cookie.mapToCookie({sid:'value'}) === 'sid=value',
            cookie.getCookie('https://example.invalid/') === ''
        ].join('|')"#;
        assert_eq!(
            eval_js(input, "", "https://example.invalid/").unwrap(),
            "true|true|true|true|true",
        );
    }

    #[test]
    fn audit_simple_response_preserves_duplicate_headers_and_response_cookies() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/cookies", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            write!(stream, "HTTP/1.1 200 OK\r\nSet-Cookie: sid=first; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/\r\nSet-Cookie: token=a=b=c; Path=/\r\nX-Multi: first\r\nX-Multi: second\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
        });
        let initial = ExecuteSession {
            cookies: Some("unrelated=session".to_string()),
            ..Default::default()
        };
        let (result, _) = with_active_session(Some(&initial), &url, |_| {
            eval_js(&format!("const r=java.get('{}', {{}}); [r.cookie('sid'),r.cookie('token'),r.cookie('missing') === null,r.hasCookie('token'),r.hasCookie('unrelated'),r.cookies().get('sid'),r.multiHeaders().get('set-cookie').length,r.multiHeaders().get('x-multi').join(','),r.body(),cookie.mapToCookie(r.cookies())].join('|')", url), "", &url).unwrap()
        });
        assert_eq!(
            result,
            "first|a=b=c|true|true|false|first|2|first,second|ok|sid=first; token=a=b=c"
        );
        server.join().unwrap();
    }

    #[test]
    fn simple_http_response_parse_preserves_charset_bytes_and_base_uri() {
        let html = "<meta charset='GBK'><title>中文</title><a href='../chapter'>正文</a>";
        let gbk = encoding_rs::GBK.encode(html).0.into_owned();
        for (content_type, bytes, initial_charset, initial_matches) in [
            ("text/html", gbk.clone(), "null", false),
            ("text/html; charset=\"GBK\"", gbk, "GBK", true),
            (
                "text/html; charset=GBK",
                [b"\xef\xbb\xbf".as_slice(), html.as_bytes()].concat(),
                "GBK",
                false,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/dir/index", listener.local_addr().unwrap());
            let byte_count = bytes.len();
            let server = thread::spawn(move || {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
                stream.write_all(&bytes).unwrap();
            });
            let script = format!(
                r#"const r=java.get('{url}', {{}});
                const initial=[String(r.charset()),r.body().includes('中文')];
                const d=r.parse(); const a=d.selectFirst('a');
                JSON.stringify([initial,d.title(),a.text(),a.absUrl('href'),
                    a.attr('abs:href'),d.baseUri(),a.baseUri(),
                    d.selectFirst('.absent')===null,r.body().includes('中文'),
                    r.bodyAsBytes().length,r.charset(),r.parse().title()])"#
            );
            let result = with_js_http_client(&HttpClient::standalone(), || {
                eval_js(&script, "", &url).unwrap()
            });
            server.join().unwrap();
            let value: serde_json::Value = serde_json::from_str(&result).unwrap();
            let base = url::Url::parse(&url)
                .unwrap()
                .join("../chapter")
                .unwrap()
                .to_string();
            assert_eq!(
                value,
                serde_json::json!([
                    [initial_charset, initial_matches],
                    "中文",
                    "正文",
                    base,
                    base,
                    url,
                    url,
                    true,
                    true,
                    byte_count,
                    if content_type == "text/html; charset=GBK" {
                        "UTF-8"
                    } else {
                        "GBK"
                    },
                    "中文"
                ])
            );
        }
    }

    #[test]
    fn simple_http_response_preserves_binary_bytes_and_text_behavior() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/bytes", listener.local_addr().unwrap());
        let bytes = [0, 255, 128, b'A'];
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 8192);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.write_all(&bytes).unwrap();
        });
        let result = with_js_http_client(&HttpClient::standalone(), || {
            eval_js(
                &format!(
                    r#"const response = java.get('{url}', {{}});
                const bytes = response.bodyAsBytes(); bytes[0] = 7;
                [response.bodyAsBytes().join(','), response.body() === '\u0000\ufffd\ufffdA',
                 response.statusCode()].join('|')"#
                ),
                "",
                &url,
            )
            .unwrap()
        });
        server.join().unwrap();
        assert_eq!(result, "0,255,128,65|true|200");
    }

    #[test]
    fn simple_http_methods_do_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });

        let url = format!("http://{address}/redirect");
        let client = HttpClient::standalone();
        let result = with_js_http_client(&client, || {
            eval_js(
                &format!(
                    "(() => {{ const response = java.get('{url}', {{}}); return [response.code(), response.header('location'), response.url()].join('|'); }})()"
                ),
                "",
                &url,
            )
            .unwrap()
        });
        assert_eq!(result, format!("302|/final|{url}"));
        server.join().unwrap();
    }

    #[test]
    fn digest_hmac_url_and_system_helpers_match_legado_shapes() {
        let script = r#"
            const parsed = java.toURL(
                '../p?q=first&q=last&name=a+b&flag',
                'https://example.com/base/x'
            );
            const logTypeResult = java.logType('reader');
            [
                java.digestHex('abc', 'SHA-256'),
                java.digestBase64Str('abc', 'SHA-256'),
                java.HMacHex('abc', 'HmacSHA256', 'key'),
                java.HMacBase64('abc', 'HmacSHA256', 'key'),
                parsed.host,
                parsed.origin,
                parsed.pathname,
                parsed.searchParams.get('q'),
                parsed.searchParams.get('name'),
                parsed.searchParams.get('flag'),
                java.getWebViewUA().startsWith('Mozilla/5.0'),
                typeof logTypeResult === 'undefined'
            ].join('|')
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad|ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=|9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab|nBluMtwBdfhvSxy4konWYZ3mvuaZ5MN45oMJ7Zehpqs=|example.com|https://example.com|/p|last|a b||true|true"
        );
        assert!(eval_js(
            "java.digestHex('abc', 'unsupported')",
            "",
            "https://example.com"
        )
        .is_err());
    }

    #[test]
    fn java_get_reads_legado_book_and_chapter_variable_scopes() {
        let bindings = HashMap::from([
            (
                "book".to_string(),
                json!({
                    "name": "Book",
                    "variableMap": {
                        "bookOnly": "book-value",
                        "shadowed": "book-value",
                        "headers": r#"{"headers":{"X-Test":"ok"}}"#
                    }
                }),
            ),
            (
                "chapter".to_string(),
                json!({
                    "title": "Chapter",
                    "variableMap": {
                        "chapterOnly": "chapter-value",
                        "shadowed": "chapter-value"
                    }
                }),
            ),
            ("title".to_string(), json!("Chapter")),
        ]);

        let result = eval_js_with_bindings(
            "[java.get('bookOnly'), java.get('chapterOnly'), java.get('shadowed'), java.put('shadowed', 'updated'), java.get('shadowed'), java.get('headers'), java.get('bookName'), java.get('title')].join('|')",
            "",
            "https://example.com",
            &bindings,
        )
        .unwrap();
        assert_eq!(
            result,
            r#"book-value|chapter-value|chapter-value|updated|updated|{"headers":{"X-Test":"ok"}}|Book|Chapter"#
        );
    }

    #[test]
    fn login_header_map_handles_missing_invalid_and_valid_headers() {
        let url = "https://headers.example/books";
        let (missing, unchanged) = with_active_session(None, url, |_| {
            eval_js("source.getLoginHeaderMap() === null", "", url).unwrap()
        });
        assert_eq!(missing, "true");
        assert!(unchanged.is_none());

        let invalid = ExecuteSession {
            header: Some(json!("not JSON")),
            ..Default::default()
        };
        let (bad, unchanged) = with_active_session(Some(&invalid), url, |_| {
            eval_js("source.getLoginHeaderMap() === null", "", url).unwrap()
        });
        assert_eq!(bad, "true");
        assert!(unchanged.is_none());

        let non_object = ExecuteSession {
            header: Some(json!("[1,2]")),
            ..Default::default()
        };
        let (bad_type, _) = with_active_session(Some(&non_object), url, |_| {
            eval_js("source.getLoginHeaderMap() === null", "", url).unwrap()
        });
        assert_eq!(bad_type, "true");

        let valid = ExecuteSession {
            header: Some(json!({"X-Reader": "ok", "X-Count": "2"})),
            ..Default::default()
        };
        let (result, unchanged) = with_active_session(Some(&valid), url, |_| {
            eval_js(
                "const headers = source.getLoginHeaderMap(); [headers instanceof Map, headers.size, headers.get('X-Reader'), headers.get('X-Count')].join('|')",
                "",
                url,
            )
            .unwrap()
        });
        assert_eq!(result, "true|2|ok|2");
        assert!(unchanged.is_none());
    }

    #[test]
    fn test_js_session_bindings() {
        let initial = ExecuteSession {
            cookies: Some("sid=initial_token".to_string()),
            cookie_jar: None,
            header: Some(json!({"Authorization": "Bearer init_auth"})),
            variables: Some(
                [("myVar".to_string(), json!("initial_val"))]
                    .into_iter()
                    .collect(),
            ),
        };

        let (_, delta) =
            with_active_session(Some(&initial), "https://example.com/books", |_session| {
                // Read initial variable
                let res =
                    eval_js("source.getVariable('myVar')", "", "https://example.com").unwrap();
                assert_eq!(res, "initial_val");

                // Write new variable
                let res = eval_js(
                    "source.setVariable('myVar', 'updated_val')",
                    "",
                    "https://example.com",
                )
                .unwrap();
                assert_eq!(res, "");
                assert_eq!(
                    eval_js("source.getVariable('myVar')", "", "https://example.com").unwrap(),
                    "updated_val"
                );

                // Read login header
                let h = eval_js("source.getLoginHeader()", "", "https://example.com").unwrap();
                assert!(h.contains("init_auth"));
                assert_eq!(
                    eval_js(
                        "source.getLoginHeaderMap().get('Authorization')",
                        "",
                        "https://example.com"
                    )
                    .unwrap(),
                    "Bearer init_auth"
                );

                // Put new login header with Cookie
                eval_js(
                    r#"source.putLoginHeader(JSON.stringify({Cookie: "sid=refreshed_token"}))"#,
                    "",
                    "https://example.com",
                )
                .unwrap();

                // Cookie get
                let c = eval_js(
                    "cookie.getCookie('https://example.com')",
                    "",
                    "https://example.com",
                )
                .unwrap();
                assert!(c.contains("sid=refreshed_token"));
            });

        assert!(delta.is_some());
        let delta = delta.unwrap();
        assert_eq!(delta.cookies, Some("sid=refreshed_token".to_string()));
        assert_eq!(
            delta
                .variables
                .as_ref()
                .unwrap()
                .get("myVar")
                .and_then(JsonValue::as_str),
            Some("updated_val")
        );
    }

    #[test]
    fn compat_java_xpath_strings_join_and_interleave() {
        let body = "<root><a>A1</a><a>A2</a><b>B1</b><b>B2</b><b>B3</b><c>C1</c></root>";

        assert_eq!(
            java_get_string(
                Some("@XPath://a"),
                Some(body),
                "",
                "https://example.com",
                false,
                false,
            ),
            "A1\nA2"
        );
        assert_eq!(
            java_get_string_list(
                Some("@XPath://a/text()%%@XPath://b/text()%%@XPath://c/text()"),
                Some(body),
                "",
                "https://example.com",
                false,
            ),
            vec!["A1", "B1", "C1", "A2", "B2"]
        );
    }

    #[test]
    fn xml_node_context_preserves_case_relative_ancestor_and_sibling_queries() {
        let body = r#"<?xml version="1.0"?><Root><Item><Child>Value</Child></Item><Sibling>Other</Sibling></Root>"#;
        let output = eval_js(
            r#"
            const item = java.getElement('//Item', result);
            [item.select('./Child').size(), item.select('.//Child').size(),
             item.select('.//child').size(), item.select('@xpath:parent::Root').size(),
             item.select('@xpath:following-sibling::Sibling').size(),
             item.select('@xpath:/Root/Sibling').size()].join('|')
        "#,
            body,
            "https://fixture.test",
        )
        .unwrap();
        assert_eq!(output, "1|1|0|1|1|1");
    }

    #[test]
    fn xml_node_context_preserves_qualified_attributes_and_non_html_void_content() {
        let body = r#"<?xml version="1.0"?><root xmlns:x="urn:x" xmlns:y="urn:y"><x:Item id="plain" x:id="X" y:id="Y"><x:Child>V</x:Child><link>https://fixture.test/a</link></x:Item></root>"#;
        let output = eval_js(
            r#"
            const item = java.getElement('//x:Item', result);
            const link = java.getElement('//link', result);
            [item.attr('id'), item.attr('x:id'), item.attr('y:id'),
             item.select('.//x:Child').size(),
             item.outerHtml().includes('urn:x'), item.outerHtml().includes('urn:y'),
             link.outerHtml().includes('https://fixture.test/a'),
             link.html()].join('|')
        "#,
            body,
            "https://fixture.test",
        )
        .unwrap();
        assert_eq!(output, "plain|X|Y|1|true|true|true|https://fixture.test/a");
    }

    #[test]
    fn xml_node_context_helpers_keep_css_and_json_conversion_paths() {
        for body in [
            r#"<?xml version="1.0"?><Root><Item><Child class="kid">Value</Child></Item></Root>"#,
            r#"<div><section id="item"><span class="kid">Value</span></section></div>"#,
        ] {
            let output = eval_js(r#"
                const item = java.getElement('//Item', result) || java.getElement('//section', result);
                [java.getElements('.kid', item).size(),
                 java.getElements('@css:.kid', item).size(),
                 java.getElements('.kid', item, true).size(),
                 java.getString('.kid@text', item),
                 java.getStringList('.kid@text', item).join(','),
                 java.getStringList('$.a[*]', {a:[1,2]}).join(',')].join('|')
            "#, body, "https://fixture.test").unwrap();
            assert_eq!(output, "1|1|1|Value|Value|1,2");
        }
    }

    #[test]
    fn xml_node_context_uses_local_namespace_and_preserves_xml_inner_html() {
        let body = r#"<?xml version="1.0"?><root xmlns:x="urn:outer"><x:Child>Outer</x:Child><branch xmlns:x="urn:inner"><x:Child>Inner</x:Child><link>URL</link></branch></root>"#;
        let output = eval_js(
            r#"
            const branch = java.getElement('//branch', result);
            [branch.select('./x:Child').first().text(),
             java.getString('@xpath:./html()', branch).includes('URL'),
             java.getString('@xpath:./html()', branch).includes('x:Child')].join('|')
        "#,
            body,
            "https://fixture.test",
        )
        .unwrap();
        assert_eq!(output, "Inner|true|true");
    }

    #[test]
    fn xml_node_context_document_pool_is_shared_and_evaluation_local() {
        let items: String = (0..200)
            .map(|index| format!("<Item><Child>{index}</Child></Item>"))
            .collect();
        let body = format!(
            "<?xml version=\"1.0\"?><Root><noise>{}</noise>{items}</Root>",
            "x".repeat(64 * 1024)
        );
        let output = eval_js(r#"
            const items = java.getElements('//Item', result);
            const again = java.getElements('//Item', result);
            [items.size(), new Set(items.map(item => item.__readerXPathNode.documentId)).size,
             items[0].__readerXPathNode.documentId === again[0].__readerXPathNode.documentId,
             JSON.stringify(items).length < 60000,
             items.get(100).select('./Child').first().text(),
             items.get(100).select('@xpath:preceding-sibling::Item[1]/Child').first().text()].join('|')
        "#, &body, "https://fixture.test").unwrap();
        assert_eq!(output, "200|1|true|true|100|99");
        let output = eval_js(
            r#"java.getElement('//Item', result).__readerXPathNode.documentId"#,
            &body,
            "https://fixture.test",
        )
        .unwrap();
        assert_eq!(output, "0");
    }

    #[test]
    fn xml_node_context_document_pool_rejects_excess_distinct_documents() {
        let output = eval_js(r#"
            let rejected = false;
            try {
                for (let i = 0; i < 65; i++) {
                    java.getElements('//Item', '<?xml version="1.0"?><Root><Item>' + i + '</Item></Root>');
                }
            } catch (error) { rejected = error instanceof RangeError; }
            String(rejected)
        "#, "", "https://fixture.test").unwrap();
        assert_eq!(output, "true");
    }

    #[test]
    fn xml_node_context_is_accepted_by_java_query_helpers() {
        let body = r#"<?xml version="1.0"?><Root><Item><Child>One</Child><Child>Two</Child></Item></Root>"#;
        let output = eval_js(
            r#"
            const item = java.getElement('//Item', result);
            const child = java.getElement('@xpath:./Child', item);
            [java.getString('@xpath:./Child', item),
             java.getStringList('@xpath:./Child', item).join(','),
             java.getElements('@xpath:./Child', item).size(),
             child === null ? 'missing' : child.text()].join('|')
        "#,
            body,
            "https://fixture.test",
        )
        .unwrap();
        assert_eq!(output, "One\nTwo|One,Two|2|One");
    }

    #[test]
    fn compat_java_get_elements_supports_xpath_element_chaining() {
        let body = r#"<div id="catalog"><a href="/ch1" class="c-link">Chapter One</a><a href="/ch2" class="c-link">Chapter Two</a></div>"#;
        let script = r#"
            const items = java.getElements('//div[@id="catalog"]//a', result);
            const first = items.first();
            const last = items.get(1);
            [items.size(), first.attr('href'), first.text(), first.hasClass('c-link'), last.attr('href'), last.text()].join('|')
        "#;
        let output = eval_js(script, body, "https://example.com").unwrap();
        assert_eq!(output, "2|/ch1|Chapter One|true|/ch2|Chapter Two");
    }

    #[test]
    fn compat_java_get_elements_advanced_xpath_chaining() {
        let body = r#"
            <div id="catalog">
                <div class="header">
                    <img src="/cover.jpg" alt="Cover Image" />
                    <span class="count">Total: 2</span>
                </div>
                <ul class="chapters">
                    <li><a href="/ch1" class="c-link">Chapter One</a></li>
                    <li><a href="/ch2" class="c-link">Chapter Two</a></li>
                </ul>
            </div>
            <div id="footer">The End</div>
        "#;

        // 1. Test getElement singular, id() function, select() chaining with XPath
        let script = r#"
            const root = java.getElement('id("catalog")', result);
            const img = root.select('.//img').first();
            const links = root.select('.//ul/li/a');
            const footer = java.getElement('id("footer")', result);
            const missing = java.getElement('id("nonexistent")', result);

            [
                root.attr('id'),
                img.attr('src'),
                img.attr('alt'),
                links.size(),
                links.get(0).attr('href'),
                links.get(0).text(),
                links.get(1).attr('href'),
                links.get(1).text(),
                footer.text(),
                missing === null
            ].join('|')
        "#;
        let output = eval_js(script, body, "https://example.com").unwrap();
        assert_eq!(
            output,
            "catalog|/cover.jpg|Cover Image|2|/ch1|Chapter One|/ch2|Chapter Two|The End|true"
        );

        // 2. Test XPath direct attribute query and text node query in java.getElements
        let script_attrs = r#"
            const hrefs = java.getElements('//ul[@class="chapters"]//a/@href', result);
            const texts = java.getElements('//ul[@class="chapters"]//a/text()', result);
            [hrefs.size(), hrefs.get(0), hrefs.get(1), texts.size(), texts.get(0), texts.get(1)].join('|')
        "#;
        let output_attrs = eval_js(script_attrs, body, "https://example.com").unwrap();
        assert_eq!(output_attrs, "2|/ch1|/ch2|2|Chapter One|Chapter Two");

        // 3. Test mixed XPath and CSS chaining: select XPath root then select CSS
        let script_mixed = r#"
            const catalog = java.getElement('//div[@id="catalog"]', result);
            const span = catalog.select('span.count').first();
            const link = catalog.select('ul li a').first();
            [span.text(), span.attr('class'), link.attr('href')].join('|')
        "#;
        let output_mixed = eval_js(script_mixed, body, "https://example.com").unwrap();
        assert_eq!(output_mixed, "Total: 2|count|/ch1");

        // 4. All java string APIs share the same XPath mode detection, including id().
        let script_strings = r#"
            const footer = java.getString('id("footer")/text()', result);
            const hrefs = java.getStringList('id("catalog")//a/@href', result);
            [footer, hrefs.join(',')].join('|')
        "#;
        let output_strings = eval_js(script_strings, body, "https://example.com").unwrap();
        assert_eq!(output_strings, "The End|/ch1,/ch2");
    }
}
