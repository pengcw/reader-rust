// Limited DOM projection; the native Await entry installs this only for opted-in HTML.
// The caller supplies an opaque page ID. Only registered current links dispatch.
(function(pageId) {
    if (!/^[A-Za-z0-9_-]+$/.test(pageId)) throw new Error('invalid page ID');
    let revision = 0;
    let targets = new Map();
    const inlineHandlers = new WeakMap();
    const selector = 'input,textarea,select,button,[onclick],[role="button"]';
    const available = node => {
        if (node.hasAttribute('disabled') || node.disabled === true || node.getAttribute('aria-disabled') === 'true') return false;
        for (let parent = node; parent && parent.nodeType === 1; parent = parent.parentElement) {
            if (parent.hasAttribute('hidden') || parent.style.display === 'none') return false;
        }
        return true;
    };
    const kindOf = node => {
        if (!available(node)) return null;
        if (node.localName === 'textarea') return node.hasAttribute('readonly') ? null : 'input';
        if (node.localName === 'input') {
            const type = (node.getAttribute('type') || 'text').toLowerCase();
            if ((type === 'text' || type === 'password' || type === 'color') && !node.hasAttribute('readonly')) return 'input';
            if (type === 'button' || type === 'checkbox') return 'click';
            return null;
        }
        return node.localName === 'select' || node.localName === 'button' || node.hasAttribute('onclick')
            || typeof node.onclick === 'function' || node.getAttribute('role') === 'button' ? 'click' : null;
    };
    // LinkeDOM supports handler properties/listeners, but does not compile HTML
    // onclick attributes. Bind the clicked path in its own page global scope.
    const bindEventPath = (node, type) => {
        const property = 'on' + type;
        for (let current = node; current && current.nodeType === 1; current = current.parentElement) {
            const source = current.getAttribute(property);
            const records = inlineHandlers.get(current);
            const previous = records && records[property];
            if (previous && current[property] === previous.handler) {
                if (source === previous.source) continue;
                current[property] = null;
            }
            if (typeof current[property] === 'function' || source === null) continue;
            // pi-lens-ignore: ast-grep:no-global-eval-js
            const compiled = new Function('event', source);
            const handler = function(event) {
                if (compiled.call(this, event) === false) event.preventDefault();
            };
            current[property] = handler;
            const handlers = records || {};
            handlers[property] = {source, handler};
            inlineHandlers.set(current, handlers);
        }
    };
    return {
        snapshot() {
            revision++;
            targets = new Map();
            const copy = document.documentElement.cloneNode(true);
            // Both queries must exclude the <html> root, or indices diverge.
            const originals = Array.from(document.documentElement.querySelectorAll(selector));
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
            const labelText = label => {
                const copy = label.cloneNode(true);
                copy.querySelectorAll('input,textarea,select,button,script,style').forEach(node => node.remove());
                return copy.textContent.replace(/\s+/g, ' ').trim();
            };
            const labels = new Map();
            document.querySelectorAll('label[for]').forEach(label => {
                const id = label.getAttribute('for');
                if (!labels.has(id)) labels.set(id, labelText(label));
            });
            const controlName = node => {
                const label = node.closest('label');
                return (node.getAttribute('aria-label') || labels.get(node.id)
                    || (label && labelText(label)) || node.getAttribute('title') || '').trim();
            };
            const actions = [];
            originals.forEach((node, index) => {
                const clone = projected[index];
                const password = node.localName === 'input'
                    && (node.getAttribute('type') || '').toLowerCase() === 'password';
                if (password) clone.removeAttribute('value');
                const kind = kindOf(node);
                if (!kind) return;
                const name = controlName(node);
                const prefix = name ? name + '：' : '';
                if (node.localName === 'select') {
                    const options = Array.from(node.querySelectorAll('option'));
                    const choices = document.createElement('div');
                    const selectedValue = String(node.value);
                    options.forEach((option, position) => {
                        if (option.disabled || option.hasAttribute('disabled')
                            || option.closest('optgroup[disabled]')) return;
                        const uri = 'legado-action:/' + pageId + '/' + revision + '/' + index + '/' + position;
                        const link = document.createElement('a');
                        link.setAttribute('href', uri);
                        link.classList.add('legado-click');
                        const optionValue = option.getAttribute('value') ?? option.textContent;
                        const selected = selectedValue === optionValue;
                        link.textContent = '[' + prefix + (selected ? '已选' : '选择') + '：' + option.textContent.trim() + ']';
                        choices.appendChild(link);
                        targets.set(uri, {node, kind, option});
                        actions.push({uri, kind});
                    });
                    if (choices.firstChild) clone.replaceWith(choices);
                    return;
                }
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
                    if (name) action.label = name;
                    const hint = node.getAttribute('placeholder');
                    if (hint) action.hint = hint;
                    if ((node.getAttribute('type') || '').toLowerCase() === 'color') {
                        action.inputType = 'color';
                        if (!action.hint) action.hint = '#RRGGBB，如 #aabbcc';
                    }
                    if (node.localName === 'textarea') action.multiline = true;
                    action.value = String(node.value || '');
                    link.textContent = password ? '[' + (name || '密码') + '：编辑]' : '[' + prefix + (action.value || '空') + '：编辑]';
                } else {
                    link.textContent = node.localName === 'input' && (node.getAttribute('type') || '').toLowerCase() === 'checkbox'
                        ? '[' + prefix + (node.checked ? '已勾选' : '未勾选') + ']'
                        : '[' + (node.textContent.trim() || node.getAttribute('value') || '点击') + ']';
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
            if (target.kind === 'input' && target.node.localName === 'input'
                && (target.node.getAttribute('type') || '').toLowerCase() === 'color') {
                if (!/^#[0-9a-f]{6}$/i.test(value)) return false;
                value = value.toLowerCase();
            }
            if (target.option && (!target.node.contains(target.option)
                || target.option.disabled || target.option.hasAttribute('disabled')
                || target.option.closest('optgroup[disabled]'))) return false;
            targets = new Map();
            const node = target.node;
            if (target.option) {
                node.value = target.option.getAttribute('value') ?? target.option.textContent;
                bindEventPath(node, 'change');
                node.dispatchEvent(new Event('input', {bubbles: true}));
                node.dispatchEvent(new Event('change', {bubbles: true}));
            } else if (target.kind === 'click') {
                bindEventPath(node, 'click');
                const checkbox = node.localName === 'input' && (node.getAttribute('type') || '').toLowerCase() === 'checkbox';
                if (checkbox) {
                    node.checked = !node.checked;
                    if (node.checked) node.setAttribute('checked', '');
                    else node.removeAttribute('checked');
                }
                node.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true, button: 0}));
                if (checkbox) {
                    bindEventPath(node, 'change');
                    node.dispatchEvent(new Event('input', {bubbles: true}));
                    node.dispatchEvent(new Event('change', {bubbles: true}));
                }
            } else {
                node.value = value;
                if (node.localName === 'input') node.setAttribute('value', value);
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
