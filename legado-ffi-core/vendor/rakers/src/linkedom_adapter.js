// LinkeDOM DOM adapter. Networking and scheduling remain host-owned.
function _r_initialize_linkedom(html) {
    var previous = document;
    document = _r_linkedom.parseHTML(html).document;
    // LinkeDOM reads RegExp.$1/$4/$6 while parsing DOCTYPE, which QuickJS lacks.
    // Restore the parsed node rather than patching output text after rendering.
    if (document.doctype && !document.doctype.name) {
        var declaration = /<!doctype\s+([^\s>]+)([^>]*)>/i.exec(html);
        if (declaration) {
            var ids = declaration[2].match(/"[^"]*"|'[^']*'/g) || [];
            document.doctype.name = declaration[1];
            if (/^\s*public\b/i.test(declaration[2])) {
                document.doctype.publicId = ids[0] ? ids[0].slice(1, -1) : '';
                document.doctype.systemId = ids[1] ? ids[1].slice(1, -1) : '';
            } else if (/^\s*system\b/i.test(declaration[2])) {
                document.doctype.systemId = ids[0] ? ids[0].slice(1, -1) : '';
            }
        }
    }
    globalThis.document = document;
    Object.keys(_r_linkedom).forEach(function(name) {
        if (/^(HTML|SVG|Document|Node|Element|Event|CustomEvent|DOMParser|ShadowRoot|Text|Comment)/.test(name))
            globalThis[name] = _r_linkedom[name];
    });
    // Keep LinkeDOM's real InputEvent and rebase the two missing UI event types.
    globalThis.InputEvent = _r_linkedom.InputEvent;
    if (globalThis.MouseEvent) Object.setPrototypeOf(globalThis.MouseEvent.prototype, globalThis.Event.prototype);
    if (globalThis.KeyboardEvent) Object.setPrototypeOf(globalThis.KeyboardEvent.prototype, globalThis.Event.prototype);
    var view = document.defaultView;
    globalThis.MutationObserver = view.MutationObserver;
    globalThis.customElements = view.customElements;
    // Share window listeners with the renderer's existing lifecycle dispatcher.
    view.addEventListener;
    view.addEventListener = window.addEventListener.bind(window);
    view.removeEventListener = window.removeEventListener.bind(window);
    view.dispatchEvent = window.dispatchEvent.bind(window);
    document.location = window.location;
    document.cookie = '';
    document.readyState = 'loading';
    document.write = previous.write;
    document.writeln = previous.writeln;
    document.currentScript = document.createElement('script');
    document.currentScript.src = window.location.href;
    document.implementation = {
        createHTMLDocument: function(title) {
            var doc = _r_linkedom.parseHTML('<html><head></head><body></body></html>').document;
            if (title !== undefined) doc.title = String(title);
            Object.defineProperty(doc, 'defaultView', {value:null});
            doc.implementation = document.implementation;
            return doc;
        }
    };
    // LinkeDOM does not execute scripts. Keep execution behind the host budget.
    var started = new WeakSet();
    document.querySelectorAll('script').forEach(function(script) { started.add(script); });
    function run(script) {
        if (!script || script.nodeName !== 'SCRIPT' || script.ownerDocument !== document || !script.isConnected || started.has(script)) return;
        started.add(script);
        if (script.type === 'module') return;
        if (!script.src) {
            var saved = document.currentScript;
            document.currentScript = script;
            try { (0, eval)(script.text || script.textContent || ''); }
            catch (e) { console.error('Dynamic script evaluation failed: ' + String(e)); }
            finally { document.currentScript = saved; }
            return;
        }
        window.setTimeout(function() {
            var event = 'error', saved = document.currentScript;
            try {
                var url = _r_parse_url(script.src, window.location.href).href;
                var response = JSON.parse(_r_request_sync('GET', url, '{}', '') || '{}');
                if (!response.error && response.status >= 200 && response.status < 300) {
                    event = 'load'; document.currentScript = script;
                    try { (0, eval)(String(response.body || '')); }
                    catch (e) { console.error('Dynamic script evaluation failed: ' + String(e)); }
                }
            } catch (e) {} finally { document.currentScript = saved; }
            script.dispatchEvent(new _r_linkedom.Event(event));
        }, 0);
    }
    // LinkeDOM's ParentNode overrides Node.insertBefore; hook the actual insertion methods.
    var parentProto = Object.getPrototypeOf(_r_linkedom.Element.prototype);
    // Markup parsing must remain inert even though LinkeDOM uses insertion methods internally.
    var inertMarkup = 0, elementProto = _r_linkedom.Element.prototype;
    var htmlAccessors = Object.getOwnPropertyDescriptor(elementProto, 'innerHTML');
    Object.defineProperty(elementProto, 'innerHTML', {
        get: htmlAccessors.get,
        set: function(value) {
            inertMarkup++;
            try { return htmlAccessors.set.call(this, value); }
            finally { inertMarkup--; }
        },
        configurable: true
    });
    var insertAdjacentHTML = elementProto.insertAdjacentHTML;
    elementProto.insertAdjacentHTML = function(position, html) {
        inertMarkup++;
        try { return insertAdjacentHTML.call(this, position, html); }
        finally { inertMarkup--; }
    };
    function insertedScripts(node) {
        if (!node || typeof node !== 'object') return [];
        if (node.nodeName === 'SCRIPT') return [node];
        // DocumentFragment empties during insertion, so capture its scripts beforehand.
        if (node.nodeType === 11 && typeof node.querySelectorAll === 'function')
            return Array.from(node.querySelectorAll('script'));
        return [];
    }
    ['insertBefore','append','prepend','replaceChildren'].forEach(function(name) {
        var original = parentProto[name];
        parentProto[name] = function() {
            var scripts = [];
            if (!inertMarkup) for (var i = 0; i < arguments.length; i++)
                scripts.push.apply(scripts, insertedScripts(arguments[i]));
            var result = original.apply(this, arguments);
            if (!inertMarkup) scripts.forEach(run);
            return result;
        };
    });
    window.Image = function(width, height) {
        var image = document.createElement('img'), pending = 0;
        image.width = width === undefined ? 0 : Number(width) >>> 0;
        image.height = height === undefined ? 0 : Number(height) >>> 0;
        image.complete = true; image.naturalWidth = 0; image.naturalHeight = 0;
        Object.defineProperty(image, 'src', {
            get: function() { return image.getAttribute('src') || ''; },
            set: function(value) {
                image.setAttribute('src', String(value));
                if (pending) clearTimeout(pending);
                image.complete = !String(value);
                if (String(value)) pending = setTimeout(function() {
                    pending = 0; image.complete = true;
                    image.dispatchEvent(new _r_linkedom.Event('error'));
                }, 0);
            }
        });
        return image;
    };
    window.Image.prototype = _r_linkedom.HTMLImageElement.prototype;
    function readyStateChanged(state) {
        document.readyState = state;
        var event = new _r_linkedom.Event('readystatechange');
        document.dispatchEvent(event);
        // LinkeDOM dispatchEvent does not invoke onreadystatechange properties.
        if (typeof document.onreadystatechange === 'function') {
            try { document.onreadystatechange.call(document, event); }
            catch (e) { console.error('[rakers event error]', e && (e.message || String(e))); }
        }
    }
    _r_dispatch_dom_content_loaded = function() {
        readyStateChanged('interactive');
        document.dispatchEvent(new _r_linkedom.Event('DOMContentLoaded'));
        window.performance.timing.domContentLoadedEventEnd = Date.now();
    };
    _r_dispatch_load = function() {
        readyStateChanged('complete');
        window.dispatchEvent({type:'load'});
        window.performance.timing.loadEventEnd = Date.now();
    };
}
