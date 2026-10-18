// Limited DOM projection; the native Await entry installs this only for opted-in HTML.
// The caller supplies an opaque page ID. Only registered current links dispatch.
(function(pageId) {
    if (!/^[A-Za-z0-9_-]+$/.test(pageId)) throw new Error('invalid page ID');
    let revision = 0;
    let targets = new Map();
    const inlineHandlers = new WeakMap();
    const selector = 'input,button,[onclick],[role="button"]';
    const available = node => {
        if (node.hasAttribute('disabled') || node.getAttribute('aria-disabled') === 'true') return false;
        for (let parent = node; parent && parent.nodeType === 1; parent = parent.parentElement) {
            if (parent.hasAttribute('hidden') || parent.style.display === 'none') return false;
        }
        return true;
    };
    const kindOf = node => {
        if (!available(node)) return null;
        if (node.localName === 'input') {
            const type = (node.getAttribute('type') || 'text').toLowerCase();
            if ((type === 'text' || type === 'password') && !node.hasAttribute('readonly')) return 'input';
            if (type === 'button') return 'click';
            return null;
        }
        return node.localName === 'button' || node.hasAttribute('onclick')
            || typeof node.onclick === 'function' || node.getAttribute('role') === 'button' ? 'click' : null;
    };
    // LinkeDOM supports handler properties/listeners, but does not compile HTML
    // onclick attributes. Bind the clicked path in its own page global scope.
    const bindClickPath = node => {
        for (let current = node; current && current.nodeType === 1; current = current.parentElement) {
            const source = current.getAttribute('onclick');
            const previous = inlineHandlers.get(current);
            if (previous && current.onclick === previous.handler) {
                if (source === previous.source) continue;
                current.onclick = null;
            }
            if (typeof current.onclick === 'function' || source === null) continue;
            // pi-lens-ignore: ast-grep:no-global-eval-js
            const compiled = new Function('event', source);
            const handler = function(event) {
                if (compiled.call(this, event) === false) event.preventDefault();
            };
            current.onclick = handler;
            inlineHandlers.set(current, {source, handler});
        }
    };
    return {
        snapshot() {
            revision++;
            targets = new Map();
            const copy = document.documentElement.cloneNode(true);
            const originals = Array.from(document.querySelectorAll(selector));
            const projected = Array.from(copy.querySelectorAll(selector));
            // Property-assigned onclick is not reflected as an [onclick] attribute.
            // Append those candidates after normal controls to preserve their IDs.
            const descendants = document.documentElement.querySelectorAll('*');
            const clonedDescendants = copy.querySelectorAll('*');
            const dynamicParents = new Set();
            descendants.forEach((node, index) => {
                if (typeof node.onclick !== 'function' || node.matches(selector)) return;
                originals.push(node);
                projected.push(clonedDescendants[index]);
                for (let parent = node.parentElement; parent; parent = parent.parentElement) {
                    dynamicParents.add(parent);
                }
            });
            const actions = [];
            originals.forEach((node, index) => {
                const clone = projected[index];
                const password = node.localName === 'input'
                    && (node.getAttribute('type') || '').toLowerCase() === 'password';
                if (password) clone.removeAttribute('value');
                const kind = kindOf(node);
                if (!kind) return;
                const uri = 'legado-action:/' + pageId + '/' + revision + '/' + index;
                const link = document.createElement('a');
                link.setAttribute('href', uri);
                for (const name of ['class', 'style', 'title']) {
                    const attribute = clone.getAttribute(name);
                    if (attribute !== null) link.setAttribute(name, attribute);
                }
                // Display-only styling hook; never modify the live DOM or action URI.
                link.classList.add(kind === 'input' ? 'legado-input' : 'legado-click');
                const action = {uri, kind};
                if (kind === 'input') {
                    action.password = password;
                    action.value = String(node.value || '');
                    link.textContent = password ? '[密码：编辑]' : '[' + (action.value || '空') + '：编辑]';
                } else {
                    link.textContent = '[' + (node.textContent.trim() || node.getAttribute('value') || '点击') + ']';
                }
                // Avoid wrapping nested controls in nested anchors. Container
                // actions get a separate entry; leaf controls become the link.
                if (clone.querySelector(selector) || dynamicParents.has(node)) {
                    link.textContent = '[操作]';
                    clone.insertBefore(link, clone.firstChild);
                } else {
                    clone.replaceWith(link);
                }
                targets.set(uri, {node, kind});
                actions.push(action);
            });
            // HtmlBox wraps its input as body content. Give its native css option
            // the page styles instead of nesting a second head inside that body.
            const css = Array.from(copy.querySelectorAll('style'), node => node.textContent).join('\n');
            copy.querySelectorAll('script,style').forEach(node => node.remove());
            const body = copy.querySelector('body') || copy;
            return {revision, html: body.innerHTML, css, actions};
        },
        apply(uri, value, expectedKind) {
            const target = targets.get(uri);
            if (!target || !document.documentElement.contains(target.node)
                || kindOf(target.node) !== target.kind
                || (expectedKind && expectedKind !== target.kind)) return false;
            if (target.kind === 'input' && typeof value !== 'string') return false;
            targets = new Map();
            const node = target.node;
            if (target.kind === 'click') {
                bindClickPath(node);
                node.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true, button: 0}));
            } else {
                node.value = value;
                node.setAttribute('value', value);
                node.dispatchEvent(new Event('input', {bubbles: true}));
                node.dispatchEvent(new Event('change', {bubbles: true}));
            }
            return true;
        },
        body() {
            return document.documentElement.outerHTML;
        }
    };
})
