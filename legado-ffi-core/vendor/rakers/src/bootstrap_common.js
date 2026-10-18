// rakers browser-globals bootstrap.
// Evaluated before every user script. Rust supplies the initial URL and User-Agent as JS values.

var window = globalThis;
var self   = window;
var global = window;

// QuickJS searches every position on failed non-sticky matches, even for ^.
// Delegate an unambiguously anchored, non-stateful pattern to a private native
// sticky copy. Never rewrite the pattern or alter the caller's lastIndex.
(function() {
    var NativeRegExp = RegExp;
    var nativeExec = NativeRegExp.prototype.exec;
    var sourceGetter = Object.getOwnPropertyDescriptor(NativeRegExp.prototype, 'source').get;
    var flagGetters = [['hasIndices','d'],['global','g'],['ignoreCase','i'],['multiline','m'],
                       ['dotAll','s'],['unicode','u'],['unicodeSets','v'],['sticky','y']]
        .map(function(pair) {
            var descriptor = Object.getOwnPropertyDescriptor(NativeRegExp.prototype, pair[0]);
            return descriptor && descriptor.get ? [descriptor.get, pair[1]] : null;
        }).filter(function(pair) { return pair !== null; });
    var copies = new WeakMap();
    NativeRegExp.prototype.exec = function exec(input) {
        if (typeof input !== 'string') return nativeExec.call(this, input);
        var copy;
        try {
            copy = copies.get(this);
            if (copy === undefined) {
                // Intrinsic getters ignore page-defined source/flag overrides.
                var source = sourceGetter.call(this), flags = '';
                flagGetters.forEach(function(pair) { if (pair[0].call(this)) flags += pair[1]; }, this);
                copy = source[0] === '^' && source.indexOf('|') < 0 && flags.indexOf('g') < 0 && flags.indexOf('m') < 0 && flags.indexOf('y') < 0
                    ? new NativeRegExp(source, flags + 'y') : null;
                copies.set(this, copy);
            }
        } catch (e) { return nativeExec.call(this, input); }
        // Non-numeric indexes may have coercion side effects; leave them native.
        if (!copy || this.lastIndex !== 0) return nativeExec.call(this, input);
        copy.lastIndex = 0;
        return nativeExec.call(copy, input);
    };
})();

// Node.js-style globals that bundlers (webpack/vite) reference at runtime.
// React/Vue/Angular all gate dev-mode warnings on process.env.NODE_ENV.
var process = {
    env: { NODE_ENV: 'production' },
    browser: true, version: 'v18.0.0', versions: {},
    nextTick: function(fn) {}  // some polyfill shims (e.g. promise-polyfill) call process.nextTick
};

// Minimal EventTarget used by window, document, and synthetic elements. Rakers only
// needs target-local listeners for page bootstrapping; capture/bubble are intentionally
// out of scope for the browser simulation.
function _r_install_event_target(target) {
    if (!target || target._r_listeners) return target;
    Object.defineProperty(target, '_r_listeners', {value:{}, writable:true, configurable:true});
    target.addEventListener = function(type, listener) {
        type = String(type || '');
        if (!type || (!listener || (typeof listener !== 'function' && typeof listener.handleEvent !== 'function'))) return;
        var list = this._r_listeners[type] || (this._r_listeners[type] = []);
        if (list.indexOf(listener) < 0) list.push(listener);
    };
    target.removeEventListener = function(type, listener) {
        var list = this._r_listeners[String(type || '')];
        if (!list) return;
        var i = list.indexOf(listener);
        if (i >= 0) list.splice(i, 1);
    };
    target.dispatchEvent = function(event) {
        if (typeof event === 'string') event = {type:event};
        if (!event || !event.type) return true;
        if (typeof event.preventDefault !== 'function') {
            event.defaultPrevented = false;
            event.preventDefault = function() { if (event.cancelable) event.defaultPrevented = true; };
        }
        event.target = event.target || this;
        event.currentTarget = this;
        var list = (this._r_listeners[String(event.type)] || []).slice();
        for (var i = 0; i < list.length; i++) {
            try {
                if (typeof list[i] === 'function') list[i].call(this, event);
                else list[i].handleEvent.call(list[i], event);
            } catch(e) {}
        }
        var handler = this['on' + event.type];
        if (typeof handler === 'function') { try { handler.call(this, event); } catch(e) {} }
        return !event.defaultPrevented;
    };
    return target;
}

// ─── URL parser (used by element setAttribute and window.URL) ───────────────

function _r_parse_url(href, base) {
    var parsed = JSON.parse(_r_url_parse(String(href || ''), base == null ? '' : String(base)));
    if (!parsed) throw new TypeError('Invalid URL');
    return parsed;
}


// ─── window ──────────────────────────────────────────────────────────────────

(function() {
    var _u = _r_parse_url(typeof globalThis.__r_initial_href === 'string'
        ? globalThis.__r_initial_href : 'about:blank');
    var _hash = _u.hash;
    var _loc = {
        href:     _u.href,     protocol: _u.protocol, host:     _u.host,
        hostname: _u.hostname, port:     _u.port,     pathname: _u.pathname,
        search:   _u.search,   origin:   _u.origin,
        assign: function() {}, replace: function() {}, reload: function() {},
        toString: function() { return this.href; }
    };
    // Mithril: sets window.location.hash = '#/' when no route matches, then relies on
    // window.onhashchange to re-trigger routing and render the default route.
    Object.defineProperty(_loc, 'hash', {
        get: function() { return _hash; },
        set: function(v) {
            var prev = _hash;
            _hash = String(v);
            if (prev !== _hash) {
                window.setTimeout(function() {
                    window.dispatchEvent({ type: 'hashchange', oldURL: prev, newURL: _hash });
                }, 0);
            }
        },
        enumerable: true, configurable: true
    });
    window.location = _loc;
    document.location = _loc;
})();
window.navigator = {
    userAgent: typeof globalThis.__r_initial_ua === 'string'
        ? globalThis.__r_initial_ua : 'rakers/0.1.0', appName: 'rakers', appVersion: '0.1.0',
    language: 'en-US', languages: ['en-US', 'en'],
    platform: 'Linux', vendor: '',
    onLine: true, cookieEnabled: true,
    javaEnabled: function() { return false; }
};
window.screen = {width:1920, height:1080, availWidth:1920, availHeight:1080, colorDepth:24};
// Angular router uses history.pushState for navigation; Mithril uses replaceState
// during its initial route redirect (m.route with mode='hash').
window.history = {
    length: 1, scrollRestoration: 'auto', state: null,
    pushState:    function(s) { this.state = s || null; },
    replaceState: function(s) { this.state = s || null; },
    back: function() {}, forward: function() {}, go: function() {}
};
window.performance = {
    now:               function() { return 0; },
    mark:              function() {}, measure: function() {},
    getEntriesByType:  function() { return []; },
    getEntriesByName:  function() { return []; },
    clearMarks:        function() {}, clearMeasures: function() {},
    timing:  { navigationStart: 0, domContentLoadedEventEnd: 0, loadEventEnd: 0 },
    memory:  { usedJSHeapSize: 0, jsHeapSizeLimit: 2147483648 }
};
// Mithril TodoMVC: persists todos to localStorage; Aurelia and Backbone TodoMVC do the same.
window.localStorage = {
    _s: {}, length: 0,
    getItem:    function(k) { return Object.prototype.hasOwnProperty.call(this._s, k) ? this._s[k] : null; },
    setItem:    function(k, v) { this._s[k] = String(v); },
    removeItem: function(k) { delete this._s[k]; },
    clear:      function()  { this._s = {}; },
    key:        function()  { return null; }
};
window.sessionStorage = {
    _s: {}, length: 0,
    getItem:    function(k) { return Object.prototype.hasOwnProperty.call(this._s, k) ? this._s[k] : null; },
    setItem:    function(k, v) { this._s[k] = String(v); },
    removeItem: function(k) { delete this._s[k]; },
    clear:      function()  { this._s = {}; },
    key:        function()  { return null; }
};
// Pull-based virtual timer loop. Rust advances to the next deadline rather than
// sleeping, so browser ordering is preserved without turning the renderer async.
var _r_timer_epoch = Date.now();
var _r_virtual_now = 0;
var _r_timers = {};
var _r_next_timer_id = 1;
Date.now = function() { return _r_timer_epoch + _r_virtual_now; };
window.performance.now = function() { return _r_virtual_now; };
window.performance.timing.navigationStart = _r_timer_epoch;
window.performance.timeOrigin = _r_timer_epoch;

function _r_schedule_timer(fn, delay, interval) {
    if (typeof fn !== 'function') return 0;
    delay = Math.max(0, Number(delay) || 0);
    var id = _r_next_timer_id++;
    _r_timers[id] = { callback:fn, deadline:_r_virtual_now + delay, interval:interval };
    return id;
}
window.setTimeout = function(fn, delay) { return _r_schedule_timer(fn, delay, null); };
window.clearTimeout = function(id) { delete _r_timers[id]; };
window.setInterval = function(fn, delay) {
    delay = Math.max(1, Number(delay) || 1);
    return _r_schedule_timer(fn, delay, delay);
};
window.clearInterval = window.clearTimeout;
window.requestAnimationFrame = function(fn) {
    return window.setTimeout(function() { fn(_r_virtual_now); }, 16);
};
window.cancelAnimationFrame = window.clearTimeout;
window.queueMicrotask = function(fn) { if (typeof fn === 'function') Promise.resolve().then(fn); };
process.nextTick = window.queueMicrotask;
window.setImmediate = function(fn) { return window.setTimeout(fn, 0); };
window.clearImmediate = window.clearTimeout;

// Execute exactly one earliest timer. Rust drains QuickJS's microtask queue after
// every call, matching the browser rule that each timer callback is its own task.
globalThis._r_pump_timers = function(maxVirtualMs) {
    var nextId = null;
    var nextDeadline = Infinity;
    var ids = Object.keys(_r_timers);
    for (var i = 0; i < ids.length; i++) {
        var id = ids[i];
        var timer = _r_timers[id];
        if (!timer) continue;
        if (timer.deadline < nextDeadline
            || (timer.deadline === nextDeadline && Number(id) < Number(nextId))) {
            nextId = id;
            nextDeadline = timer.deadline;
        }
    }
    if (nextId == null || nextDeadline > maxVirtualMs) return 0;
    if (nextDeadline > _r_virtual_now) _r_virtual_now = nextDeadline;
    var timer = _r_timers[nextId];
    if (!timer) return 0;
    if (timer.interval == null) delete _r_timers[nextId];
    else timer.deadline = _r_virtual_now + timer.interval;
    try { timer.callback(); } catch(e) {
        if (typeof console !== 'undefined') console.error('[rakers timer error]', e && (e.message || String(e)));
    }
    return 1;
};

globalThis._r_dispatch_dom_content_loaded = function() {
    document.readyState = 'interactive';
    document.dispatchEvent({type:'readystatechange'});
    document.dispatchEvent({type:'DOMContentLoaded'});
    window.performance.timing.domContentLoadedEventEnd = Date.now();
};
globalThis._r_dispatch_load = function() {
    document.readyState = 'complete';
    document.dispatchEvent({type:'readystatechange'});
    window.dispatchEvent({type:'load'});
    window.performance.timing.loadEventEnd = Date.now();
};
window.alert   = function(msg) {};
window.confirm = function(msg) { return false; };
window.prompt  = function(msg, def) { return null; };
window.open    = function() { return null; };
window.close   = function() {};
window.postMessage     = function() {};
window.Headers = function(init) {
    this._h = {};
    var self = this;
    var put = function(k, v, append) {
        k = String(k || '').toLowerCase();
        if (!k) return;
        v = String(v == null ? '' : v);
        self._h[k] = append && self._h[k] ? self._h[k] + ', ' + v : v;
    };
    if (init instanceof window.Headers) {
        init.forEach(function(v, k) { put(k, v, false); });
    } else if (Array.isArray(init)) {
        init.forEach(function(pair) { if (pair && pair.length >= 2) put(pair[0], pair[1], true); });
    } else if (init && typeof init === 'object') {
        Object.keys(init).forEach(function(k) { put(k, init[k], false); });
    }
    this.append = function(k, v) { put(k, v, true); };
    this.set = function(k, v) { put(k, v, false); };
    this.get = function(k) { k=String(k||'').toLowerCase(); return Object.prototype.hasOwnProperty.call(this._h,k) ? this._h[k] : null; };
    this.has = function(k) { return this.get(k) !== null; };
    this.delete = function(k) { delete this._h[String(k||'').toLowerCase()]; };
    this.forEach = function(fn) { Object.keys(this._h).forEach(function(k) { fn(self._h[k], k, self); }); };
    this.entries = function() { return Object.keys(this._h).map(function(k) { return [k, self._h[k]]; }); };
};

function _r_headers_object(headers) {
    var out = {};
    if (!headers) return out;
    var h = headers instanceof window.Headers ? headers : new window.Headers(headers);
    h.forEach(function(v, k) { out[k] = v; });
    return out;
}

function _r_make_response(raw, requestedUrl) {
    var bodyText = String(raw.body == null ? '' : raw.body);
    var headers = new window.Headers(raw.headers || {});
    var response = {
        ok: Number(raw.status) >= 200 && Number(raw.status) < 300,
        status: Number(raw.status) || 0,
        statusText: String(raw.statusText || ''),
        url: String(raw.url || requestedUrl || ''),
        redirected: !!raw.url && String(raw.url) !== String(requestedUrl || ''),
        type: 'basic',
        bodyUsed: false,
        headers: headers,
        text: function() { this.bodyUsed = true; return Promise.resolve(bodyText); },
        json: function() {
            this.bodyUsed = true;
            try { return Promise.resolve(JSON.parse(bodyText)); }
            catch (e) { return Promise.reject(e); }
        },
        blob: function() { this.bodyUsed = true; return Promise.resolve(new window.Blob([bodyText])); },
        arrayBuffer: function() { this.bodyUsed = true; return Promise.resolve(null); },
        clone: function() { return _r_make_response(raw, requestedUrl); }
    };
    return response;
}

var _r_pending_fetches = Object.create(null);
globalThis._r_async_complete = function(id, raw) {
    var pending = _r_pending_fetches[id];
    if (!pending) return;
    delete _r_pending_fetches[id];
    try {
        var response = JSON.parse(raw || '{}');
        if (response.error) pending.reject(new Error(String(response.error)));
        else pending.resolve(_r_make_response(response, pending.url));
    } catch (error) { pending.reject(error); }
};

window.fetch = function(input, init) {
    init = init || {};
    var inputObj = input && typeof input === 'object' ? input : null;
    var rawUrl = inputObj && inputObj.url != null ? inputObj.url : input;
    var abs = _r_parse_url(String(rawUrl || ''), window.location && window.location.href).href;
    var method = String(init.method || (inputObj && inputObj.method) || 'GET').toUpperCase();
    var headers = init.headers || (inputObj && inputObj.headers) || {};
    var body = init.body;
    if (body == null && inputObj) body = inputObj.body;
    body = body == null ? '' : String(body);
    return new Promise(function(resolve, reject) {
        if (typeof _r_request_sync !== 'function') {
            reject(new Error('Rakers HTTP bridge is unavailable'));
            return;
        }
        try {
            var requestHeaders = JSON.stringify(_r_headers_object(headers));
            if (typeof _r_request_async_start === 'function') {
                var queued = JSON.parse(_r_request_async_start(method, abs, requestHeaders, body) || '{}');
                if (queued.error || !queued.id) reject(new Error(String(queued.error || 'HTTP request not queued')));
                else _r_pending_fetches[queued.id] = {resolve: resolve, reject: reject, url: abs};
                return;
            }
            var raw = JSON.parse(_r_request_sync(method, abs, requestHeaders, body) || '{}');
            // A synchronous transport must not make network completion a
            // parser-script microtask: later inline configuration is not ready yet.
            window.setTimeout(function() {
                if (raw.error) reject(new Error(String(raw.error)));
                else resolve(_r_make_response(raw, abs));
            }, 0);
        } catch (e) {
            reject(e);
        }
    });
};

window.Request = function(input, init) {
    init = init || {};
    this.url = _r_parse_url(String(input && input.url || input || ''), window.location && window.location.href).href;
    this.method = String(init.method || input && input.method || 'GET').toUpperCase();
    this.headers = new window.Headers(init.headers || input && input.headers || {});
    this.body = init.body == null ? (input && input.body || '') : init.body;
};
window.Response = function(body, init) {
    init = init || {};
    return _r_make_response({
        body: body == null ? '' : String(body),
        status: init.status == null ? 200 : Number(init.status),
        statusText: init.statusText || '',
        headers: _r_headers_object(init.headers || {}),
        url: ''
    }, '');
};

// Keep the legacy synchronous helper for dynamically inserted scripts and sync XHR.
window._r_fetch_sync = function(url) {
    if (typeof _r_request_sync !== 'function') return '';
    try {
        var abs = _r_parse_url(String(url || ''), window.location && window.location.href).href;
        var raw = JSON.parse(_r_request_sync('GET', abs, '{}', '') || '{}');
        var status = Number(raw.status) || 0;
        return raw.error || status < 200 || status >= 300 ? '' : String(raw.body == null ? '' : raw.body);
    } catch (e) { return ''; }
};

window.XMLHttpRequest = function() {
    var self = this;
    this.readyState=0; this.status=0; this.statusText='';
    this.responseText=''; this.responseXML=null; this.response='';
    this.responseURL=''; this.responseType=''; this.withCredentials=false; this.timeout=0;
    this.onreadystatechange=null; this.onload=null; this.onerror=null;
    this.onloadstart=null; this.onloadend=null; this.onprogress=null; this.ontimeout=null; this.onabort=null;
    this._url=''; this._method='GET'; this._async=true; this._headers={}; this._responseHeaders={};
    this._listeners={}; this._aborted=false;

    function fire(type) {
        var event = {type:type,target:self};
        var handler = self['on' + type];
        if (typeof handler === 'function') try { handler.call(self, event); } catch(e) {}
        var list = self._listeners[type] || [];
        list.slice().forEach(function(fn) { try { fn.call(self, event); } catch(e) {} });
    }
    function state(value) {
        self.readyState = value;
        fire('readystatechange');
    }
    function applyResponse(raw) {
        self.status = Number(raw.status) || 0;
        self.statusText = String(raw.statusText || '');
        self.responseURL = String(raw.url || self._url);
        self._responseHeaders = _r_headers_object(raw.headers || {});
        state(2);
        state(3);
        self.responseText = String(raw.body == null ? '' : raw.body);
        if (self.responseType === 'json') {
            try { self.response = JSON.parse(self.responseText); } catch(e) { self.response = null; }
        } else {
            self.response = self.responseText;
        }
        state(4);
        fire('load');
        fire('loadend');
    }
    function fail() {
        state(4);
        fire('error');
        fire('loadend');
    }

    this.open=function(method, url, async) {
        self._method = String(method || 'GET').toUpperCase();
        self._url = String(url || '');
        self._async = (async !== false);
        self._aborted = false;
        state(1);
    };
    this.setRequestHeader=function(k,v){ self._headers[String(k)] = String(v); };
    this.getResponseHeader=function(k){
        var key=String(k||'').toLowerCase();
        var names=Object.keys(self._responseHeaders);
        for (var i=0;i<names.length;i++) if (names[i].toLowerCase()===key) return self._responseHeaders[names[i]];
        return null;
    };
    this.getAllResponseHeaders=function(){
        return Object.keys(self._responseHeaders).map(function(k){return k+': '+self._responseHeaders[k]+'\r\n';}).join('');
    };
    this.send=function(body) {
        var abs = _r_parse_url(self._url, window.location && window.location.href).href;
        var payload = body == null ? '' : String(body);
        fire('loadstart');
        if (!self._async) {
            if (typeof _r_request_sync !== 'function') { fail(); return; }
            try {
                var raw = JSON.parse(_r_request_sync(self._method, abs, JSON.stringify(self._headers), payload) || '{}');
                if (raw.error) { fail(); return; }
                applyResponse(raw);
            } catch(e) { fail(); }
            return;
        }
        window.fetch(abs, {method:self._method, headers:self._headers, body:payload})
            .then(function(resp) {
                self.status=resp.status; self.statusText=resp.statusText; self.responseURL=resp.url;
                self._responseHeaders=_r_headers_object(resp.headers);
                state(2); state(3);
                return resp.text();
            })
            .then(function(text) {
                if (self._aborted) return;
                self.responseText=String(text == null ? '' : text);
                if (self.responseType==='json') {
                    try { self.response=JSON.parse(self.responseText); } catch(e) { self.response=null; }
                } else self.response=self.responseText;
                state(4); fire('load'); fire('loadend');
            })
            .catch(function(){ if (!self._aborted) fail(); });
    };
    this.abort=function(){ self._aborted=true; state(4); fire('abort'); fire('loadend'); };
    this.overrideMimeType=function(){};
    this.addEventListener=function(t,fn){
        if (!self._listeners[t]) self._listeners[t]=[];
        self._listeners[t].push(fn);
    };
    this.removeEventListener=function(t,fn){
        if (!self._listeners[t]) return;
        self._listeners[t]=self._listeners[t].filter(function(f){return f!==fn;});
    };
    this.dispatchEvent=function(){return true;};
};
window.XMLHttpRequest.UNSENT=0;
window.XMLHttpRequest.OPENED=1;
window.XMLHttpRequest.HEADERS_RECEIVED=2;
window.XMLHttpRequest.LOADING=3;
window.XMLHttpRequest.DONE=4;
// FormData retains ordered duplicate values; binary File/Blob transport is not simulated.
window.FormData = function(form) {
    this._entries = [];
    if (form === undefined) return;
    if (!form || String(form.tagName || '').toUpperCase() !== 'FORM')
        throw new TypeError('FormData requires a form element');
    var controls = [];
    function collect(parent) {
        var nodes = parent.children || parent._kids || [];
        for (var i = 0; i < nodes.length; i++) {
            var node = nodes[i], tag = String(node.tagName || '').toUpperCase();
            if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || tag === 'BUTTON')
                controls.push(node);
            collect(node);
        }
    }
    collect(form);
    for (var i = 0; i < controls.length; i++) {
        var control = controls[i], tag = control.tagName.toUpperCase();
        var name = control.getAttribute('name');
        if (name === null || control.hasAttribute('disabled')) continue;
        var type = String(control.getAttribute('type') || '').toLowerCase();
        if (tag === 'BUTTON' || type === 'button' || type === 'reset' || type === 'submit' || type === 'image' || type === 'file') continue;
        if (type === 'checkbox' || type === 'radio') {
            if (!control.checked && !control.hasAttribute('checked')) continue;
            this.append(name, control.hasAttribute('value') ? control.value : 'on');
        } else if (tag === 'SELECT') {
            var options = control.options || control.children || [];
            var selected = [];
            for (var j = 0; j < options.length; j++) {
                var option = options[j];
                if (option.selected || option.hasAttribute('selected')) selected.push(option);
            }
            if (!selected.length && !control.hasAttribute('multiple') && options.length) selected.push(options[0]);
            for (var j = 0; j < selected.length; j++) {
                var option = selected[j];
                if (!option.hasAttribute('disabled'))
                    this.append(name, option.hasAttribute('value') ? option.value : option.textContent);
            }
        } else this.append(name, control.value == null ? '' : control.value);
    }
};
window.FormData.prototype.append = function(name, value) {
    if (arguments.length < 2) throw new TypeError('FormData.append requires two arguments');
    this._entries.push([String(name), String(value)]);
};
window.FormData.prototype.delete = function(name) {
    name = String(name);
    this._entries = this._entries.filter(function(p) { return p[0] !== name; });
};
window.FormData.prototype.get = function(name) {
    name = String(name);
    for (var i = 0; i < this._entries.length; i++)
        if (this._entries[i][0] === name) return this._entries[i][1];
    return null;
};
window.FormData.prototype.getAll = function(name) {
    name = String(name);
    return this._entries.filter(function(p) { return p[0] === name; }).map(function(p) { return p[1]; });
};
window.FormData.prototype.has = function(name) {
    name = String(name);
    return this._entries.some(function(p) { return p[0] === name; });
};
window.FormData.prototype.set = function(name, value) {
    if (arguments.length < 2) throw new TypeError('FormData.set requires two arguments');
    name = String(name); value = String(value);
    var found = false;
    this._entries = this._entries.filter(function(p) {
        if (p[0] !== name) return true;
        if (found) return false;
        p[1] = value; found = true; return true;
    });
    if (!found) this._entries.push([name, value]);
};
window.FormData.prototype.forEach = function(fn, thisArg) {
    for (var i = 0; i < this._entries.length; i++)
        fn.call(thisArg, this._entries[i][1], this._entries[i][0], this);
};
window.FormData.prototype._iterator = function(kind) {
    var self = this, index = 0, iterator = {
        next: function() {
            if (index >= self._entries.length) return {value:undefined, done:true};
            var pair = self._entries[index++];
            return {value:kind === 0 ? pair[0] : kind === 1 ? pair[1] : pair.slice(), done:false};
        }
    };
    iterator[Symbol.iterator] = function() { return this; };
    return iterator;
};
window.FormData.prototype.keys = function() { return this._iterator(0); };
window.FormData.prototype.values = function() { return this._iterator(1); };
window.FormData.prototype.entries = function() { return this._iterator(2); };
window.FormData.prototype[Symbol.iterator] = window.FormData.prototype.entries;
window.URL = function(href, base) {
    var u = _r_parse_url(String(href), base ? String(base) : (window.location && window.location.href));
    this.href = u.href; this.protocol = u.protocol; this.host = u.host;
    this.hostname = u.hostname; this.port = u.port; this.pathname = u.pathname;
    this.search = u.search; this.hash = u.hash; this.origin = u.origin;
    this.toString = function() { return this.href; };
    this.searchParams = new window.URLSearchParams(u.search);
};
window.URL.createObjectURL = function() { return ''; };
window.URL.revokeObjectURL = function() {};
window.Blob       = function(parts, opts) { this.size=0; this.type=(opts&&opts.type)||''; };
window.FileReader = function() { this.readAsText=function(){}; this.readAsDataURL=function(){}; this.addEventListener=function(){}; };
window.matchMedia   = function(q) {
    return {matches:false, media:q, addEventListener:function(){}, removeEventListener:function(){}, addListener:function(){}, removeListener:function(){}};
};
window.getComputedStyle = function(el) { return {}; };
window.requestIdleCallback  = function(fn) { return window.setTimeout(function(){ fn({didTimeout:false,timeRemaining:function(){return 0;}}); }, 1); };
window.cancelIdleCallback   = window.clearTimeout;
window.MutationObserver     = function(cb) { this.observe=function(){}; this.disconnect=function(){}; this.takeRecords=function(){return [];}; };  // Angular zone.js, Vue: patch MutationObserver to detect async DOM changes
window.ResizeObserver       = function(cb) { this.observe=function(){}; this.disconnect=function(){}; this.unobserve=function(){}; };
window.IntersectionObserver = function(cb) { this.observe=function(){}; this.disconnect=function(){}; this.unobserve=function(){}; };
window.PerformanceObserver  = function(cb) { this.observe=function(){}; this.disconnect=function(){}; };
window.CustomEvent  = function(type, init) { this.type=type; this.detail=init&&init.detail||null; this.bubbles=false; this.cancelable=false; };  // web-components, Angular: dispatch custom events
window.Event        = function(type, init) { this.type=type; this.bubbles=!!(init&&init.bubbles); this.cancelable=!!(init&&init.cancelable); };
// UI events inherit the active LinkeDOM Event implementation.
function _r_ui_event_constructor(defaults) {
    function UIEvent(type, init) {
        init = init || {};
        var event = new window.Event(type, init);
        for (var name in defaults)
            event[name] = Object.prototype.hasOwnProperty.call(init, name) ? init[name] : defaults[name];
        Object.setPrototypeOf(event, UIEvent.prototype);
        return event;
    }
    UIEvent.prototype = Object.create(window.Event.prototype);
    UIEvent.prototype.constructor = UIEvent;
    return UIEvent;
}
window.KeyboardEvent = _r_ui_event_constructor({
    key:'', code:'', location:0, repeat:false, isComposing:false,
    ctrlKey:false, shiftKey:false, altKey:false, metaKey:false
});
window.MouseEvent = _r_ui_event_constructor({
    screenX:0, screenY:0, clientX:0, clientY:0,
    ctrlKey:false, shiftKey:false, altKey:false, metaKey:false,
    button:0, buttons:0, relatedTarget:null, detail:0, view:null
});
window.TouchEvent   = window.Event;
window.InputEvent = _r_ui_event_constructor({
    data:null, inputType:'', dataTransfer:null, isComposing:false
});
window.InputEvent.prototype.getTargetRanges = function() { return []; };
window.FocusEvent   = window.Event;
window.ErrorEvent   = window.Event;
window.MessageEvent = function(type, init) { this.type=type; this.data=init&&init.data||null; };
window.PointerEvent = window.Event;
window.WheelEvent   = window.Event;
// React scheduler (>=17): uses MessageChannel to schedule work as a macrotask,
// ensuring renders happen after browser paint. port1.postMessage triggers port2.onmessage.
window.MessageChannel = function() {
    var self = this;
    this.port1 = { onmessage: null, postMessage: function(msg) {
        if (typeof self.port2.onmessage === 'function') window.setTimeout(function(){ self.port2.onmessage({data:msg}); }, 0);
    }};
    this.port2 = { onmessage: null, postMessage: function(msg) {
        if (typeof self.port1.onmessage === 'function') window.setTimeout(function(){ self.port1.onmessage({data:msg}); }, 0);
    }};
};
_r_install_event_target(window);
// Google Analytics / GTM: many pages include GA4 which references dataLayer and gtag
window.dataLayer = [];
window.gtag = function() { window.dataLayer.push(arguments); };
window.btoa = function(str) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    str = String(str); var out = '';
    for (var i = 0; i < str.length; i += 3) {
        var b0=str.charCodeAt(i), b1=i+1<str.length?str.charCodeAt(i+1):0, b2=i+2<str.length?str.charCodeAt(i+2):0;
        out += chars[b0>>2] + chars[((b0&3)<<4)|(b1>>4)];
        out += i+1<str.length ? chars[((b1&15)<<2)|(b2>>6)] : '=';
        out += i+2<str.length ? chars[b2&63] : '=';
    }
    return out;
};
window.atob = function(str) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    str = String(str).replace(/[\s=]+$/g, ''); var out = '';
    for (var i = 0; i < str.length; i += 4) {
        var c0=chars.indexOf(str[i]), c1=chars.indexOf(str[i+1]);
        var c2=i+2<str.length?chars.indexOf(str[i+2]):64, c3=i+3<str.length?chars.indexOf(str[i+3]):64;
        out += String.fromCharCode((c0<<2)|(c1>>4));
        if (c2!==64) out += String.fromCharCode(((c1&15)<<4)|(c2>>2));
        if (c3!==64) out += String.fromCharCode(((c2&3)<<6)|c3);
    }
    return out;
};
window.AbortController = function() { this.signal={aborted:false,addEventListener:function(){}}; this.abort=function(){}; };
window.AbortSignal  = {timeout:function(){return {aborted:false,addEventListener:function(){}};}};
// UTF-8 browser primitives. No native encoder or image/network dependency.
function _r_utf8_encode(input, destination) {
    var text = input === undefined ? '' : String(input);
    var grow = destination === undefined, out = grow ? [] : destination;
    var read = 0, written = 0;
    for (var i = 0; i < text.length;) {
        var cp = text.charCodeAt(i), units = 1;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            var low = text.charCodeAt(i + 1);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + low - 0xDC00;
                units = 2;
            } else cp = 0xFFFD;
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) cp = 0xFFFD;
        var width = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
        if (!grow && written + width > out.length) break;
        if (width === 1) out[written++] = cp;
        else {
            if (width === 4) out[written++] = 0xF0 | (cp >> 18);
            if (width >= 3) out[written++] = (width === 3 ? 0xE0 | (cp >> 12) : 0x80 | ((cp >> 12) & 63));
            out[written++] = (width === 2 ? 0xC0 | (cp >> 6) : 0x80 | ((cp >> 6) & 63));
            out[written++] = 0x80 | (cp & 63);
        }
        i += units;
        read = i;
    }
    return grow ? new Uint8Array(out) : { read: read, written: written };
}
window.TextEncoder = function() {};
window.TextEncoder.prototype.encode = function(input) { return _r_utf8_encode(input); };
window.TextEncoder.prototype.encodeInto = function(input, destination) {
    if (!(destination instanceof Uint8Array)) throw new TypeError('Expected Uint8Array');
    return _r_utf8_encode(input, destination);
};
Object.defineProperty(window.TextEncoder.prototype, 'encoding', { get: function() { return 'utf-8'; } });

window.TextDecoder = function(label, options) {
    if (label !== undefined && !/^(utf-8|utf8|unicode-1-1-utf-8)$/i.test(String(label).trim()))
        throw new RangeError('Unsupported encoding');
    options = options || {};
    this.fatal = !!options.fatal;
    this.ignoreBOM = !!options.ignoreBOM;
    this._pending = [];
    this._streaming = false;
    this._bomSeen = false;
};
Object.defineProperty(window.TextDecoder.prototype, 'encoding', { get: function() { return 'utf-8'; } });
window.TextDecoder.prototype.decode = function(input, options) {
    options = options || {};
    var streaming = !!options.stream, chunk;
    if (input == null) chunk = [];
    else if (input instanceof ArrayBuffer) chunk = new Uint8Array(input);
    else if (ArrayBuffer.isView(input)) chunk = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    else throw new TypeError('Expected BufferSource');
    if (!this._streaming) { this._pending = []; this._bomSeen = false; }
    var bytes = this._pending.concat(Array.from(chunk));
    this._pending = [];
    this._streaming = streaming;
    var chars = [];
    for (var i = 0; i < bytes.length;) {
        var lead = bytes[i], cp = lead, width = 1, low = 0x80, high = 0xBF;
        if (lead >= 0xC2 && lead <= 0xDF) { width = 2; cp &= 31; }
        else if (lead >= 0xE0 && lead <= 0xEF) {
            width = 3; cp &= 15;
            if (lead === 0xE0) low = 0xA0;
            if (lead === 0xED) high = 0x9F;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            width = 4; cp &= 7;
            if (lead === 0xF0) low = 0x90;
            if (lead === 0xF4) high = 0x8F;
        } else if (lead >= 0x80) width = 0;
        var valid = 1;
        while (valid < width && i + valid < bytes.length) {
            var next = bytes[i + valid];
            if (next < (valid === 1 ? low : 0x80) || next > (valid === 1 ? high : 0xBF)) break;
            cp = (cp << 6) | (next & 63);
            valid++;
        }
        if (valid < width && i + valid === bytes.length && streaming) {
            this._pending = bytes.slice(i);
            break;
        }
        if (width === 0 || valid < width) {
            if (this.fatal) throw new TypeError('Invalid UTF-8');
            cp = 0xFFFD;
            i += valid;
        } else i += width;
        if (!this._bomSeen) {
            this._bomSeen = true;
            if (cp === 0xFEFF && !this.ignoreBOM) continue;
        }
        chars.push(String.fromCodePoint(cp));
    }
    return chars.join('');
};
window.crypto       = {getRandomValues:function(a){return a;}, subtle:{}, randomUUID:function(){return '00000000-0000-0000-0000-000000000000';}};
window.CSS          = {supports:function(){return false;}, escape:function(s){return s;}};
window.DOMException = function(msg, name) { this.message=msg||''; this.name=name||'Error'; this.code=0; };
window.DOMException.prototype = Object.create(Error.prototype);
// web-components framework: calls customElements.define() to register <todo-app> etc.;
// whenDefined() is awaited before mounting.
window.customElements = {
    define: function() {}, get: function() { return undefined; },
    upgrade: function() {}, whenDefined: function() { return Promise.resolve(); }
};
// application/x-www-form-urlencoded preserves duplicate keys and insertion order.
function _r_form_decode(input) {
    var raw = String(input).replace(/\+/g, ' '), bytes = [];
    for (var i = 0; i < raw.length;) {
        if (raw[i] === '%' && /^[0-9a-fA-F]{2}$/.test(raw.slice(i + 1, i + 3))) {
            bytes.push(parseInt(raw.slice(i + 1, i + 3), 16));
            i += 3;
        } else {
            var c = raw.charCodeAt(i);
            if (c < 128) { bytes.push(c); i++; }
            else {
                var units = c >= 0xD800 && c <= 0xDBFF && raw.charCodeAt(i + 1) >= 0xDC00 && raw.charCodeAt(i + 1) <= 0xDFFF ? 2 : 1;
                var encoded = _r_utf8_encode(raw.slice(i, i + units));
                for (var j = 0; j < encoded.length; j++) bytes.push(encoded[j]);
                i += units;
            }
        }
    }
    return new window.TextDecoder().decode(new Uint8Array(bytes));
}
function _r_form_encode(input) {
    var bytes = _r_utf8_encode(String(input)), out = '';
    for (var i = 0; i < bytes.length; i++) {
        var b = bytes[i];
        if ((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122)
            || b === 42 || b === 45 || b === 46 || b === 95) out += String.fromCharCode(b);
        else if (b === 32) out += '+';
        else out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
    }
    return out;
}
window.URLSearchParams = function(init) {
    this._pairs = [];
    if (init == null) return;
    if (typeof init !== 'object') {
        var text = String(init);
        if (text[0] === '?') text = text.slice(1);
        if (!text) return;
        text.split('&').forEach(function(entry) {
            if (!entry) return;
            var pos = entry.indexOf('=');
            this._pairs.push([_r_form_decode(pos < 0 ? entry : entry.slice(0, pos)),
                              _r_form_decode(pos < 0 ? '' : entry.slice(pos + 1))]);
        }, this);
    } else if (init instanceof window.URLSearchParams) {
        this._pairs = init._pairs.map(function(pair) { return pair.slice(); });
    } else if (typeof init[Symbol.iterator] === 'function') {
        for (var pair of init) {
            if (!pair || typeof pair === 'string' || typeof pair[Symbol.iterator] !== 'function')
                throw new TypeError('Expected name/value pair');
            var values = Array.from(pair);
            if (values.length !== 2) throw new TypeError('Expected name/value pair');
            this.append(values[0], values[1]);
        }
    } else if (typeof init === 'object') {
        Object.keys(init).forEach(function(name) { this.append(name, init[name]); }, this);
    }
};
window.URLSearchParams.prototype.append = function(name, value) {
    this._pairs.push([String(name), String(value)]);
};
window.URLSearchParams.prototype.delete = function(name, value) {
    name = String(name);
    var matchValue = arguments.length > 1, val = String(value);
    this._pairs = this._pairs.filter(function(p) { return p[0] !== name || (matchValue && p[1] !== val); });
};
window.URLSearchParams.prototype.get = function(name) {
    name = String(name);
    for (var i = 0; i < this._pairs.length; i++)
        if (this._pairs[i][0] === name) return this._pairs[i][1];
    return null;
};
window.URLSearchParams.prototype.getAll = function(name) {
    name = String(name);
    return this._pairs.filter(function(p) { return p[0] === name; }).map(function(p) { return p[1]; });
};
window.URLSearchParams.prototype.has = function(name, value) {
    name = String(name);
    var matchValue = arguments.length > 1, val = String(value);
    return this._pairs.some(function(p) { return p[0] === name && (!matchValue || p[1] === val); });
};
window.URLSearchParams.prototype.set = function(name, value) {
    name = String(name); value = String(value);
    var found = false;
    this._pairs = this._pairs.filter(function(p) {
        if (p[0] !== name) return true;
        if (found) return false;
        p[1] = value; found = true; return true;
    });
    if (!found) this._pairs.push([name, value]);
};
window.URLSearchParams.prototype.sort = function() {
    this._pairs.sort(function(a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
};
window.URLSearchParams.prototype.forEach = function(fn, thisArg) {
    for (var i = 0; i < this._pairs.length; i++)
        fn.call(thisArg, this._pairs[i][1], this._pairs[i][0], this);
};
window.URLSearchParams.prototype._iterator = function(kind) {
    var self = this, index = 0;
    var iterator = {
        next: function() {
            if (index >= self._pairs.length) return {value:undefined, done:true};
            var pair = self._pairs[index++];
            return {value:kind === 0 ? pair[0] : kind === 1 ? pair[1] : pair.slice(), done:false};
        }
    };
    iterator[Symbol.iterator] = function() { return this; };
    return iterator;
};
window.URLSearchParams.prototype.keys = function() { return this._iterator(0); };
window.URLSearchParams.prototype.values = function() { return this._iterator(1); };
window.URLSearchParams.prototype.entries = function() { return this._iterator(2); };
window.URLSearchParams.prototype[Symbol.iterator] = window.URLSearchParams.prototype.entries;
window.URLSearchParams.prototype.toString = function() {
    return this._pairs.map(function(pair) {
        return _r_form_encode(pair[0]) + '=' + _r_form_encode(pair[1]);
    }).join('&');
};
Object.defineProperty(window.URLSearchParams.prototype, 'size', {
    get: function() { return this._pairs.length; }
});
// web-components: custom elements extend HTMLElement; the constructor check
// `el instanceof HTMLElement` must not throw.
window.HTMLElement         = function() {};
window.HTMLTemplateElement = function() {};
window.HTMLIFrameElement   = function() {};
window.HTMLInputElement    = function() {};
window.HTMLTextAreaElement = function() {};
window.HTMLSelectElement   = function() {};
window.HTMLButtonElement   = function() {};
window.HTMLAnchorElement   = function() {};
// The LinkeDOM adapter provides Image; image decoding remains unsupported.
window.HTMLFormElement     = function() {};
window.HTMLScriptElement   = function() {};
window.HTMLLinkElement     = function() {};
window.HTMLDivElement      = function() {};
window.HTMLSpanElement     = function() {};
window.Element      = function() {};
window.Node         = function() {};
window.EventTarget  = function() {};
window.SVGElement   = function() {};  // Vue: checks `el instanceof SVGElement` when deciding how to create elements
window.Document     = function() {};
window.DocumentFragment = function() {};
window.Window       = function Window() {};
window.ShadowRoot   = function() {};  // web-components, Svelte: shadow DOM host check
// Ember 5.x hasDOM check: self.constructor === Window.
// In QuickJS globalThis.constructor defaults to Object; override it so Ember
// recognises the environment as a real browser and enables interactive rendering.
try {
    Object.defineProperty(window, 'constructor', {
        value: window.Window, configurable: true, writable: true, enumerable: false
    });
} catch(e) { window.constructor = window.Window; }
window.devicePixelRatio = 1;
window.innerWidth  = 1920; window.innerHeight = 1080;
window.outerWidth  = 1920; window.outerHeight = 1080;
window.pageXOffset = 0;    window.pageYOffset = 0;
window.scrollX     = 0;    window.scrollY     = 0;
window.scrollTo    = function() {}; window.scroll   = function() {}; window.scrollBy = function() {};
window.print       = function() {}; window.focus    = function() {}; window.blur     = function() {};
