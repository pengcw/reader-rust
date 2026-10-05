//! JS engine abstraction used by the rendering pipeline.
//!
//! Exposes a single type [`JsRuntime`] backed by whichever engine feature is
//! enabled at compile time (`rquickjs` or `boa`).  Both backends share the same
//! public interface: create a runtime, execute a list of scripts, then read back
//! the accumulated `document.write` output, `document.body.innerHTML`, and
//! `console` messages.

#[cfg(all(feature = "boa", feature = "rquickjs"))]
compile_error!("Enable only one JS engine at a time: 'boa' or 'rquickjs'");

#[cfg(not(any(feature = "boa", feature = "rquickjs")))]
compile_error!("Enable exactly one JS engine feature: 'boa' or 'rquickjs'");

// The JS bootstrap is embedded at compile time; request context is substituted at runtime.
const BOOTSTRAP_TEMPLATE: &str = include_str!("bootstrap.js");

// The virtual scheduler advances instantly to the next deadline, but never beyond
// two seconds of page time. This is enough for startup/debounce work without waiting
// on ads, clocks, or long-poll timers.
const TIMER_PUMP_JS: &str = "_r_pump_timers(2000)";
const DOM_CONTENT_LOADED_JS: &str = "_r_dispatch_dom_content_loaded()";
const LOAD_JS: &str = "_r_dispatch_load()";

// Read the rendered DOM state after all timers and microtasks have been flushed.
const READBACK_JS: &str = r"
(function() {
    var body = document.body && document.body.innerHTML;
    if (body) return body;
    // If scripts wrote into registry elements but never appended them to body,
    // collect any that have content.
    var parts = [];
    var keys  = Object.keys(_r_reg);
    for (var i = 0; i < keys.length; i++) {
        var el = _r_reg[keys[i]];
        if (el && el.innerHTML) parts.push(_r_serialize(el));
    }
    return parts.join('');
})()
";

fn escape_js_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Produce the browser-globals bootstrap from the actual page request context.
fn make_bootstrap(page_url: Option<&str>, user_agent: Option<&str>) -> String {
    let href = escape_js_string(page_url.unwrap_or("about:blank"));
    let user_agent = escape_js_string(user_agent.unwrap_or("rakers/0.1.0"));
    // Replace placeholders with sentinels first so values that happen to contain
    // the other placeholder text are never rewritten on the second substitution.
    BOOTSTRAP_TEMPLATE
        .replace("__HREF__", "\u{1}")
        .replace("__USER_AGENT__", "\u{2}")
        .replace('\u{1}', &href)
        .replace('\u{2}', &user_agent)
}

fn request_headers_from_json(raw: &str) -> Vec<(String, String)> {
    let Ok(serde_json::Value::Object(headers)) = serde_json::from_str(raw) else {
        return Vec::new();
    };
    headers
        .into_iter()
        .filter(|(name, _)| {
            !matches!(
                name.to_ascii_lowercase().as_str(),
                "cookie"
                    | "host"
                    | "content-length"
                    | "connection"
                    | "transfer-encoding"
                    | "proxy-authorization"
            )
        })
        .filter_map(|(name, value)| match value {
            serde_json::Value::String(value) => Some((name, value)),
            serde_json::Value::Number(value) => Some((name, value.to_string())),
            serde_json::Value::Bool(value) => Some((name, value.to_string())),
            _ => None,
        })
        .collect()
}

fn perform_http_request(
    cfg: &crate::HttpConfig,
    budget: &crate::RequestBudget,
    method: &str,
    url: &str,
    headers_json: &str,
    body: &str,
) -> String {
    let mut headers = request_headers_from_json(headers_json);
    // Browser JavaScript cannot set transport-owned/credential headers directly.
    // Cookie state comes only from the host cookie jar, so script code cannot
    // replace or exfiltrate it by forging a raw Cookie header.
    headers.retain(|(name, _)| {
        !matches!(
            name.to_ascii_lowercase().as_str(),
            "cookie"
                | "host"
                | "content-length"
                | "connection"
                | "proxy-authorization"
                | "set-cookie"
                | "transfer-encoding"
                | "user-agent"
        )
    });
    match cfg.execute(
        budget,
        method,
        url,
        &headers,
        (!body.is_empty()).then_some(body),
        cfg.forward_headers,
    ) {
        Ok(response) => {
            let mut response_headers = serde_json::Map::new();
            for (name, value) in response.headers {
                if name.eq_ignore_ascii_case("set-cookie")
                    || name.eq_ignore_ascii_case("set-cookie2")
                {
                    continue;
                }
                response_headers
                    .insert(name.to_ascii_lowercase(), serde_json::Value::String(value));
            }
            let status_text = ureq::http::StatusCode::from_u16(response.status)
                .ok()
                .and_then(|status| status.canonical_reason())
                .unwrap_or("");
            serde_json::json!({
                "url": response.url,
                "status": response.status,
                "statusText": status_text,
                "headers": response_headers,
                "body": response.body,
            })
            .to_string()
        }
        Err(error) => serde_json::json!({"error": error}).to_string(),
    }
}

// ── boa engine ────────────────────────────────────────────────────────────────

#[cfg(feature = "boa")]
mod boa_rt {
    use std::cell::RefCell;

    use anyhow::anyhow;
    use boa_engine::{
        Context, JsResult, JsValue, NativeFunction, Source, js_string, object::ObjectInitializer,
        property::Attribute,
    };

    thread_local! {
        static WRITTEN:         RefCell<String>      = const { RefCell::new(String::new()) };
        static LOGGED:          RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        static BODY_INNER_HTML: RefCell<String>      = const { RefCell::new(String::new()) };
        static HTTP_CONFIG:     RefCell<Option<crate::HttpConfig>>    = const { RefCell::new(None) };
        static HTTP_BUDGET:     RefCell<Option<crate::RequestBudget>> = const { RefCell::new(None) };
    }

    struct HttpContextGuard;

    impl Drop for HttpContextGuard {
        fn drop(&mut self) {
            HTTP_CONFIG.with(|slot| *slot.borrow_mut() = None);
            HTTP_BUDGET.with(|slot| *slot.borrow_mut() = None);
        }
    }

    /// A sandboxed JavaScript execution context.
    pub struct JsRuntime;

    impl JsRuntime {
        /// Create a new runtime with a custom per-script timeout.
        ///
        /// Boa has no interrupt-handler API, so the timeout is accepted but not enforced.
        pub fn with_timeout(_timeout: std::time::Duration) -> Self {
            Self::new()
        }

        /// Create a new runtime with no per-script timeout.
        pub fn without_timeout() -> Self {
            Self::new()
        }

        fn new() -> Self {
            WRITTEN.with(|w| w.borrow_mut().clear());
            LOGGED.with(|l| l.borrow_mut().clear());
            BODY_INNER_HTML.with(|b| b.borrow_mut().clear());
            JsRuntime
        }

        /// Evaluate the browser bootstrap and then each script in `scripts` in order.
        ///
        /// Errors from individual scripts are printed to stderr and skipped; the method
        /// only returns `Err` if the bootstrap itself fails to evaluate.
        pub fn execute(
            &self,
            scripts: &[String],
            page_url: Option<&str>,
            cfg: &crate::HttpConfig,
            budget: &crate::RequestBudget,
        ) -> anyhow::Result<()> {
            self.execute_with_final_script(scripts, page_url, cfg, budget, None)
                .map(|_| ())
        }

        /// Execute a page and optionally evaluate one caller-provided script after
        /// lifecycle/timer work has settled. The script result is coerced to a string.
        pub fn execute_with_final_script(
            &self,
            scripts: &[String],
            page_url: Option<&str>,
            cfg: &crate::HttpConfig,
            budget: &crate::RequestBudget,
            final_script: Option<&str>,
        ) -> anyhow::Result<Option<String>> {
            HTTP_CONFIG.with(|slot| *slot.borrow_mut() = Some(cfg.clone()));
            HTTP_BUDGET.with(|slot| *slot.borrow_mut() = Some(budget.clone()));
            let _http_guard = HttpContextGuard;
            let mut ctx = Context::default();
            ctx.runtime_limits_mut().set_stack_size_limit(65536);
            ctx.runtime_limits_mut().set_recursion_limit(65536);
            setup_document(&mut ctx)?;
            setup_console(&mut ctx)?;
            setup_http_bridge(&mut ctx)?;

            let bootstrap = super::make_bootstrap(page_url, cfg.user_agent.as_deref());
            ctx.eval(Source::from_bytes(bootstrap.as_bytes()))
                .map_err(|e| anyhow!("bootstrap error: {:?}", e))?;

            for script in scripts {
                if let Err(e) = ctx.eval(Source::from_bytes(script.as_bytes())) {
                    eprintln!("[js error] {:?}", e);
                }
                let _ = ctx.run_jobs();
            }

            // Complete the synthetic page lifecycle, draining Promise jobs at each
            // task boundary just like the QuickJS backend.
            let _ = ctx.eval(Source::from_bytes(super::DOM_CONTENT_LOADED_JS.as_bytes()));
            let _ = ctx.run_jobs();
            let _ = ctx.eval(Source::from_bytes(super::LOAD_JS.as_bytes()));
            let _ = ctx.run_jobs();

            let mut empty_passes = 0u8;
            for _ in 0..128 {
                let fired: i32 = ctx
                    .eval(Source::from_bytes(super::TIMER_PUMP_JS.as_bytes()))
                    .ok()
                    .and_then(|v| v.to_number(&mut ctx).ok())
                    .map(|n| n as i32)
                    .unwrap_or(0);
                let _ = ctx.run_jobs();
                if fired == 0 {
                    empty_passes += 1;
                    if empty_passes >= 2 {
                        break;
                    }
                } else {
                    empty_passes = 0;
                }
            }

            let final_result = final_script.and_then(|script| {
                match ctx.eval(Source::from_bytes(script.as_bytes())) {
                    Ok(value) => {
                        let _ = ctx.run_jobs();
                        value
                            .to_string(&mut ctx)
                            .ok()
                            .map(|value| value.to_std_string_escaped())
                    }
                    Err(error) => {
                        eprintln!("[js error] {error:?}");
                        None
                    }
                }
            });

            let body_result = ctx.eval(Source::from_bytes(super::READBACK_JS.as_bytes()));
            let body_html = body_result
                .ok()
                .and_then(|v| v.to_string(&mut ctx).ok())
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();

            let body_html = match body_html.as_str() {
                "undefined" | "null" | "" => String::new(),
                s => s.to_owned(),
            };
            BODY_INNER_HTML.with(|b| *b.borrow_mut() = body_html);

            Ok(final_result)
        }

        /// Return the accumulated output of all `document.write` / `document.writeln` calls.
        pub fn written_html() -> String {
            WRITTEN.with(|w| w.borrow().clone())
        }

        /// Return the final value of `document.body.innerHTML` (or registry element content).
        pub fn body_inner_html() -> String {
            BODY_INNER_HTML.with(|b| b.borrow().clone())
        }

        /// Return all messages logged via `console.log`, `console.warn`, or `console.error`.
        pub fn logged_messages() -> Vec<String> {
            LOGGED.with(|l| l.borrow().clone())
        }
    }

    /// Register `document.write` and `document.writeln`.
    fn setup_document(ctx: &mut Context) -> anyhow::Result<()> {
        let mut init = ObjectInitializer::new(ctx);
        init.function(
            NativeFunction::from_fn_ptr(doc_write),
            js_string!("write"),
            1,
        );
        init.function(
            NativeFunction::from_fn_ptr(doc_writeln),
            js_string!("writeln"),
            1,
        );
        let obj = init.build();
        ctx.register_global_property(js_string!("document"), obj, Attribute::all())
            .map_err(|e| anyhow!("{:?}", e))?;
        Ok(())
    }

    /// Register `console.log`, `console.warn`, and `console.error`.
    fn setup_console(ctx: &mut Context) -> anyhow::Result<()> {
        let mut init = ObjectInitializer::new(ctx);
        init.function(
            NativeFunction::from_fn_ptr(console_log),
            js_string!("log"),
            0,
        );
        init.function(
            NativeFunction::from_fn_ptr(console_log),
            js_string!("warn"),
            0,
        );
        init.function(
            NativeFunction::from_fn_ptr(console_log),
            js_string!("error"),
            0,
        );
        let obj = init.build();
        ctx.register_global_property(js_string!("console"), obj, Attribute::all())
            .map_err(|e| anyhow!("{:?}", e))?;
        Ok(())
    }

    fn doc_write(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
        let s = js_first_arg_to_string(args, ctx)?;
        WRITTEN.with(|w| w.borrow_mut().push_str(&s));
        Ok(JsValue::undefined())
    }

    fn doc_writeln(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
        let s = js_first_arg_to_string(args, ctx)?;
        WRITTEN.with(|w| {
            let mut w = w.borrow_mut();
            w.push_str(&s);
            w.push('\n');
        });
        Ok(JsValue::undefined())
    }

    fn boa_request_sync(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
        let arg = |index: usize, ctx: &mut Context| -> String {
            args.get(index)
                .and_then(|value| value.to_string(ctx).ok())
                .map(|value| value.to_std_string_escaped())
                .unwrap_or_default()
        };
        let method = arg(0, ctx);
        let url = arg(1, ctx);
        let headers = arg(2, ctx);
        let body = arg(3, ctx);
        let cfg = HTTP_CONFIG.with(|slot| slot.borrow().clone());
        let budget = HTTP_BUDGET.with(|slot| slot.borrow().clone());
        let result = match (cfg, budget) {
            (Some(cfg), Some(budget)) => {
                super::perform_http_request(&cfg, &budget, &method, &url, &headers, &body)
            }
            _ => serde_json::json!({"error":"HTTP bridge is not initialized"}).to_string(),
        };
        Ok(js_string!(result).into())
    }

    fn setup_http_bridge(ctx: &mut Context) -> anyhow::Result<()> {
        let mut init = ObjectInitializer::new(ctx);
        init.function(
            NativeFunction::from_fn_ptr(boa_request_sync),
            js_string!("f"),
            4,
        );
        let obj = init.build();
        ctx.register_global_property(js_string!("__r_request_tmp"), obj, Attribute::all())
            .map_err(|e| anyhow!("{e:?}"))?;
        ctx.eval(Source::from_bytes(b"(function(){this._r_request_sync = __r_request_tmp.f; try{ delete __r_request_tmp; }catch(e){} })();"))
            .map_err(|e| anyhow!("register request fn failed: {e:?}"))?;
        Ok(())
    }

    fn console_log(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
        let parts: Vec<String> = args
            .iter()
            .map(|a| a.to_string(ctx).map(|s| s.to_std_string_escaped()))
            .collect::<Result<_, _>>()?;
        LOGGED.with(|l| l.borrow_mut().push(parts.join(" ")));
        Ok(JsValue::undefined())
    }

    fn js_first_arg_to_string(args: &[JsValue], ctx: &mut Context) -> JsResult<String> {
        args.first()
            .map(|v| v.to_string(ctx).map(|s| s.to_std_string_escaped()))
            .transpose()
            .map(|o| o.unwrap_or_default())
    }
}

#[cfg(feature = "boa")]
pub use boa_rt::JsRuntime;

// ── QuickJS engine ────────────────────────────────────────────────────────────

#[cfg(feature = "rquickjs")]
mod quickjs_rt {
    use std::cell::RefCell;
    use std::time::{Duration, Instant};

    use anyhow::anyhow;
    use rquickjs::{
        Context, Ctx, Function, Module, Object, Runtime, Value,
        context::EvalOptions,
        loader::{ImportAttributes, Loader, Resolver},
        module::Declared,
    };

    struct StubModuleSystem;

    impl Resolver for StubModuleSystem {
        fn resolve<'js>(
            &mut self,
            _ctx: &Ctx<'js>,
            _base: &str,
            name: &str,
            _attributes: Option<ImportAttributes<'js>>,
        ) -> rquickjs::Result<String> {
            Ok(name.to_string())
        }
    }

    impl Loader for StubModuleSystem {
        fn load<'js>(
            &mut self,
            ctx: &Ctx<'js>,
            name: &str,
            _attributes: Option<ImportAttributes<'js>>,
        ) -> rquickjs::Result<Module<'js, Declared>> {
            Module::declare(ctx.clone(), name, "export default {};")
        }
    }

    thread_local! {
        static WRITTEN:         RefCell<String>                        = const { RefCell::new(String::new()) };
        static LOGGED:          RefCell<Vec<String>>                   = const { RefCell::new(Vec::new()) };
        static BODY_INNER_HTML: RefCell<String>                        = const { RefCell::new(String::new()) };
        // Deadline for the currently-executing script; None means no limit active.
        static SCRIPT_DEADLINE: RefCell<Option<Instant>>               = const { RefCell::new(None) };
        static HTTP_CONFIG:     RefCell<Option<crate::HttpConfig>>     = const { RefCell::new(None) };
        static HTTP_BUDGET:     RefCell<Option<crate::RequestBudget>>  = const { RefCell::new(None) };
    }

    struct HttpContextGuard;

    impl Drop for HttpContextGuard {
        fn drop(&mut self) {
            HTTP_CONFIG.with(|slot| *slot.borrow_mut() = None);
            HTTP_BUDGET.with(|slot| *slot.borrow_mut() = None);
            SCRIPT_DEADLINE.with(|slot| *slot.borrow_mut() = None);
        }
    }

    fn bounded_deadline(
        timeout: Option<Duration>,
        render_deadline: Option<Instant>,
    ) -> Option<Instant> {
        let local = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        match (local, render_deadline) {
            (Some(local), Some(render)) => Some(local.min(render)),
            (Some(local), None) => Some(local),
            (None, render) => render,
        }
    }

    fn set_deadline(deadline: Option<Instant>) {
        SCRIPT_DEADLINE.with(|d| *d.borrow_mut() = deadline);
    }

    fn clear_deadline() {
        set_deadline(None);
    }

    // Pending jobs execute while Context::with holds the runtime lock, so use
    // Ctx directly. rquickjs 0.12 fixes interrupt handling during pending jobs,
    // allowing Promise callbacks to share the same deadline as their parent task.
    fn drain_pending_jobs(ctx: &Ctx<'_>, deadline: Option<Instant>) -> bool {
        let mut had_jobs = false;
        let mut jobs = 0usize;
        set_deadline(deadline);
        while jobs < 2_000
            && !deadline.is_some_and(|deadline| Instant::now() >= deadline)
            && ctx.execute_pending_job()
        {
            had_jobs = true;
            jobs += 1;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            // Clear a timeout exception left by an interrupted Promise job so the
            // next page script starts with a clean exception state.
            let _ = ctx.catch();
        }
        clear_deadline();
        had_jobs
    }

    const RUNTIME_MEMORY_LIMIT: usize = 32 * 1024 * 1024;
    const RUNTIME_STACK_LIMIT: usize = 512 * 1024;

    /// A sandboxed JavaScript execution context.
    pub struct JsRuntime {
        timeout: Option<Duration>,
    }

    impl JsRuntime {
        /// Create a new runtime with a custom per-script timeout (useful in tests).
        pub fn with_timeout(timeout: Duration) -> Self {
            WRITTEN.with(|w| w.borrow_mut().clear());
            LOGGED.with(|l| l.borrow_mut().clear());
            BODY_INNER_HTML.with(|b| b.borrow_mut().clear());
            JsRuntime {
                timeout: Some(timeout),
            }
        }

        /// Create a new runtime with no per-script timeout.
        pub fn without_timeout() -> Self {
            WRITTEN.with(|w| w.borrow_mut().clear());
            LOGGED.with(|l| l.borrow_mut().clear());
            BODY_INNER_HTML.with(|b| b.borrow_mut().clear());
            JsRuntime { timeout: None }
        }

        /// Evaluate the browser bootstrap and then each script in `scripts` in order.
        ///
        /// Scripts are evaluated in sloppy (non-strict) mode to match browser behaviour —
        /// assignments to undeclared globals are allowed, as used by `SvelteKit` and webpack.
        /// Errors from individual scripts are printed to stderr and skipped; the method
        /// only returns `Err` if the bootstrap itself fails to evaluate.
        pub fn execute(
            &self,
            scripts: &[String],
            page_url: Option<&str>,
            cfg: &crate::HttpConfig,
            budget: &crate::RequestBudget,
        ) -> anyhow::Result<()> {
            self.execute_with_final_script(scripts, page_url, cfg, budget, None)
                .map(|_| ())
        }

        /// Execute a page and optionally evaluate one caller-provided script after
        /// lifecycle/timer work has settled. The script result is coerced to a string.
        pub fn execute_with_final_script(
            &self,
            scripts: &[String],
            page_url: Option<&str>,
            cfg: &crate::HttpConfig,
            budget: &crate::RequestBudget,
            final_script: Option<&str>,
        ) -> anyhow::Result<Option<String>> {
            HTTP_CONFIG.with(|slot| *slot.borrow_mut() = Some(cfg.clone()));
            HTTP_BUDGET.with(|slot| *slot.borrow_mut() = Some(budget.clone()));
            let _http_guard = HttpContextGuard;

            let rt = Runtime::new().map_err(|e| anyhow!("quickjs runtime: {e:?}"))?;
            rt.set_memory_limit(RUNTIME_MEMORY_LIMIT);
            rt.set_max_stack_size(RUNTIME_STACK_LIMIT);
            rt.set_loader(StubModuleSystem, StubModuleSystem);

            // Check the per-script deadline every 10 000 opcodes to keep overhead near zero.
            rt.set_interrupt_handler(Some(Box::new({
                let mut counter = 0u32;
                move || {
                    counter = counter.wrapping_add(1);
                    if !counter.is_multiple_of(10_000) {
                        return false;
                    }
                    SCRIPT_DEADLINE.with(|d| d.borrow().is_some_and(|dl| Instant::now() > dl))
                }
            })));

            let ctx = Context::full(&rt).map_err(|e| anyhow!("quickjs context: {e:?}"))?;

            let final_result = ctx.with(|ctx| -> anyhow::Result<Option<String>> {
                setup_document(&ctx)?;
                setup_console(&ctx)?;
                setup_http_bridge(&ctx)?;

                let sloppy = || {
                    let mut options = EvalOptions::default();
                    options.global = true;
                    options.strict = false;
                    options
                };

                let render_deadline = budget.deadline();
                set_deadline(render_deadline);
                let bootstrap = super::make_bootstrap(page_url, cfg.user_agent.as_deref());
                let bootstrap_result = ctx.eval_with_options::<Value, _>(bootstrap, sloppy());
                clear_deadline();
                bootstrap_result.map_err(|e| anyhow!("bootstrap error: {e:?}"))?;

                for script in scripts {
                    if render_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        break;
                    }
                    let task_deadline = bounded_deadline(self.timeout, render_deadline);
                    set_deadline(task_deadline);
                    let result = ctx.eval_with_options::<Value, _>(script.as_str(), sloppy());
                    if result.is_err() {
                        let exc = ctx.catch();
                        if let Some(e) = exc.as_exception() {
                            let msg = e.message().unwrap_or_else(|| "unknown exception".into());
                            eprintln!("[js error] {msg}");
                            if crate::is_verbose()
                                && let Some(stack) = e.stack()
                            {
                                eprintln!("[js stack] {stack}");
                            }
                        }
                    }
                    clear_deadline();
                    drain_pending_jobs(&ctx, task_deadline);
                }

                // Initial scripts have finished: fire the minimal browser lifecycle,
                // draining promise reactions after each event before advancing timers.
                for lifecycle in [super::DOM_CONTENT_LOADED_JS, super::LOAD_JS] {
                    if render_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        break;
                    }
                    let task_deadline = bounded_deadline(self.timeout, render_deadline);
                    set_deadline(task_deadline);
                    let _ = ctx.eval_with_options::<Value, _>(lifecycle, sloppy());
                    clear_deadline();
                    drain_pending_jobs(&ctx, task_deadline);
                }

                // Alternate one virtual timer deadline with QuickJS's native job queue.
                // No real sleeping is needed, and long-lived polling is bounded by both
                // the two-second virtual horizon and the hard pass cap.
                for _ in 0..128u32 {
                    if render_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        break;
                    }
                    let task_deadline = bounded_deadline(self.timeout, render_deadline);
                    set_deadline(task_deadline);
                    let fired: i32 = ctx
                        .eval_with_options::<Value, _>(super::TIMER_PUMP_JS, sloppy())
                        .ok()
                        .and_then(|v| v.as_int())
                        .unwrap_or(0);
                    clear_deadline();
                    let had_jobs = drain_pending_jobs(&ctx, task_deadline);
                    if fired == 0 && !had_jobs {
                        break;
                    }
                }

                let final_result = if let Some(script) = final_script {
                    let task_deadline = bounded_deadline(self.timeout, render_deadline);
                    set_deadline(task_deadline);
                    let result = match ctx
                        .eval_with_options::<rquickjs::Coerced<String>, _>(script, sloppy())
                    {
                        Ok(value) => Some(value.0),
                        Err(_) => {
                            let exc = ctx.catch();
                            if let Some(error) = exc.as_exception() {
                                let message = error
                                    .message()
                                    .unwrap_or_else(|| "unknown exception".into());
                                eprintln!("[js error] {message}");
                            }
                            None
                        }
                    };
                    clear_deadline();
                    drain_pending_jobs(&ctx, task_deadline);
                    result
                } else {
                    None
                };

                set_deadline(bounded_deadline(self.timeout, render_deadline));
                let body_html: String = ctx
                    .eval_with_options::<Value, _>(super::READBACK_JS, sloppy())
                    .ok()
                    .and_then(|v| v.as_string().and_then(|s| s.to_string().ok()))
                    .unwrap_or_default();
                clear_deadline();

                let body_html = match body_html.as_str() {
                    "undefined" | "null" | "" => String::new(),
                    s => s.to_owned(),
                };
                BODY_INNER_HTML.with(|b| *b.borrow_mut() = body_html);

                Ok(final_result)
            })?;

            Ok(final_result)
        }

        /// Return the accumulated output of all `document.write` / `document.writeln` calls.
        pub fn written_html() -> String {
            WRITTEN.with(|w| w.borrow().clone())
        }

        /// Return the final value of `document.body.innerHTML` (or registry element content).
        pub fn body_inner_html() -> String {
            BODY_INNER_HTML.with(|b| b.borrow().clone())
        }

        /// Return all messages logged via `console.log`, `console.warn`, or `console.error`.
        pub fn logged_messages() -> Vec<String> {
            LOGGED.with(|l| l.borrow().clone())
        }
    }

    /// Register `document.write` and `document.writeln`.
    fn setup_document(ctx: &Ctx<'_>) -> anyhow::Result<()> {
        let doc = Object::new(ctx.clone()).map_err(|e| anyhow!("{e:?}"))?;

        doc.set(
            "write",
            Function::new(ctx.clone(), |s: String| {
                WRITTEN.with(|w| w.borrow_mut().push_str(&s));
                Ok::<(), rquickjs::Error>(())
            })
            .map_err(|e| anyhow!("{e:?}"))?,
        )
        .map_err(|e| anyhow!("{e:?}"))?;

        doc.set(
            "writeln",
            Function::new(ctx.clone(), |s: String| {
                WRITTEN.with(|w| {
                    let mut w = w.borrow_mut();
                    w.push_str(&s);
                    w.push('\n');
                });
                Ok::<(), rquickjs::Error>(())
            })
            .map_err(|e| anyhow!("{e:?}"))?,
        )
        .map_err(|e| anyhow!("{e:?}"))?;

        ctx.globals()
            .set("document", doc)
            .map_err(|e| anyhow!("{e:?}"))?;
        Ok(())
    }

    /// Register `console.log`, `console.warn`, and `console.error`.
    fn setup_console(ctx: &Ctx<'_>) -> anyhow::Result<()> {
        use rquickjs::function::Rest;

        let console = Object::new(ctx.clone()).map_err(|e| anyhow!("{e:?}"))?;

        let log_fn = Function::new(ctx.clone(), |args: Rest<rquickjs::Coerced<String>>| {
            let parts: Vec<String> = args.0.into_iter().map(|s| s.0).collect();
            LOGGED.with(|l| l.borrow_mut().push(parts.join(" ")));
            Ok::<(), rquickjs::Error>(())
        })
        .map_err(|e| anyhow!("{e:?}"))?;

        let noop_fn = Function::new(ctx.clone(), || Ok::<(), rquickjs::Error>(()))
            .map_err(|e| anyhow!("{e:?}"))?;

        console
            .set("log", log_fn.clone())
            .map_err(|e| anyhow!("{e:?}"))?;
        console
            .set("warn", log_fn.clone())
            .map_err(|e| anyhow!("{e:?}"))?;
        console
            .set("error", log_fn.clone())
            .map_err(|e| anyhow!("{e:?}"))?;
        console
            .set("info", log_fn.clone())
            .map_err(|e| anyhow!("{e:?}"))?;
        console.set("debug", log_fn).map_err(|e| anyhow!("{e:?}"))?;
        console
            .set("table", noop_fn.clone())
            .map_err(|e| anyhow!("{e:?}"))?;
        console
            .set("group", noop_fn.clone())
            .map_err(|e| anyhow!("{e:?}"))?;
        console
            .set("groupEnd", noop_fn.clone())
            .map_err(|e| anyhow!("{e:?}"))?;
        console
            .set("groupCollapsed", noop_fn.clone())
            .map_err(|e| anyhow!("{e:?}"))?;
        console
            .set("time", noop_fn.clone())
            .map_err(|e| anyhow!("{e:?}"))?;
        console
            .set("timeEnd", noop_fn.clone())
            .map_err(|e| anyhow!("{e:?}"))?;
        console
            .set("assert", noop_fn)
            .map_err(|e| anyhow!("{e:?}"))?;

        ctx.globals()
            .set("console", console)
            .map_err(|e| anyhow!("{e:?}"))?;
        Ok(())
    }

    /// Register the single native HTTP bridge used by fetch, XHR and dynamic scripts.
    fn setup_http_bridge(ctx: &Ctx<'_>) -> anyhow::Result<()> {
        let request_fn = Function::new(
            ctx.clone(),
            |method: String, url: String, headers: String, body: String| -> String {
                let cfg = HTTP_CONFIG.with(|slot| slot.borrow().clone());
                let budget = HTTP_BUDGET.with(|slot| slot.borrow().clone());
                match (cfg, budget) {
                    (Some(cfg), Some(budget)) => {
                        super::perform_http_request(&cfg, &budget, &method, &url, &headers, &body)
                    }
                    _ => serde_json::json!({"error":"HTTP bridge is not initialized"}).to_string(),
                }
            },
        )
        .map_err(|e| anyhow!("{e:?}"))?;

        ctx.globals()
            .set("_r_request_sync", request_fn)
            .map_err(|e| anyhow!("{e:?}"))?;
        Ok(())
    }
}

#[cfg(feature = "rquickjs")]
pub use quickjs_rt::JsRuntime;
