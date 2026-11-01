(function() {
                    const NativeMap = globalThis.Map;
                    let wrapText;
                    java.__installJsoupStringWrapper = wrapper => {
                        wrapText = wrapper;
                        delete java.__installJsoupStringWrapper;
                    };
                    const wrapStringMethods = (target, names) => {
                        for (const name of names) {
                            const original = target[name];
                            if (typeof original !== 'function') continue;
                            target[name] = function(...args) {
                                const value = original.apply(this, args);
                                return typeof value === 'string' ? wrapText(value) : value;
                            };
                        }
                        return target;
                    };
                    const elementStringMethods = ['html', 'outerHtml', 'text', 'ownText',
                        'data', 'attr', 'absUrl', 'tagName', 'nodeName', 'id', 'className'];
                    const elementsOuterHtml = function() {
                        return this.map(item => item.outerHtml()).join('\n');
                    };
                    const asObject = value => value && (typeof value === 'object' || typeof value === 'function')
                        ? value : {};
                    globalThis.org = asObject(globalThis.org);
                    globalThis.org.jsoup = asObject(globalThis.org.jsoup);
                    globalThis.org.jsoup.Jsoup = asObject(globalThis.org.jsoup.Jsoup);
                    const fetchedDocuments = new WeakMap();
                    java.__jsoupDocumentResult = value => fetchedDocuments.get(value);
                    globalThis.org.jsoup.select = asObject(globalThis.org.jsoup.select);
                    globalThis.org.jsoup.nodes = asObject(globalThis.org.jsoup.nodes);
                    if (typeof globalThis.org.jsoup.select.Elements !== 'function') {
                        globalThis.org.jsoup.select.Elements = class Elements extends Array {
                            add(element) { this.push(element); return true; }
                            size() { return this.length; }
                            get(index) { return this[Number(index)] ?? null; }
                            first() { return this.length ? this[0] : null; }
                            last() { return this.length ? this[this.length - 1] : null; }
                            isEmpty() { return this.length === 0; }
                            contains(element) { return this.some(item => item === element); }
                            outerHtml() { return elementsOuterHtml.call(this); }
                            toString() { return elementsOuterHtml.call(this); }
                            toArray() { return Array.from(this); }
                        };
                    }
                    globalThis.org.jsoup.parser = asObject(globalThis.org.jsoup.parser);
                    globalThis.org.jsoup.parser.Parser = asObject(globalThis.org.jsoup.parser.Parser);
                    if (typeof globalThis.org.jsoup.parser.Parser.unescapeEntities !== 'function') {
                        // Use the existing HTML5 parser, preserving a single entity decode pass.
                        // Attributes and text have different rules for semicolon-less entities.
                        globalThis.org.jsoup.parser.Parser.unescapeEntities = function(input, inAttribute) {
                            if (input == null) throw new TypeError('HTML entity input must be a string');
                            const value = String(input);
                            if (!value.includes('&')) return value;
                            const Jsoup = globalThis.org.jsoup.Jsoup;
                            if (inAttribute) {
                                const escaped = value.replace(/</g, '&lt;').replace(/"/g, '&quot;');
                                const span = Jsoup.parse('<span data-jsoup-encoded="' + escaped + '"></span>').selectFirst('span');
                                return span ? span.attr('data-jsoup-encoded') : value;
                            }
                            // Entity decoding must preserve literal spaces; Element.text()
                            // intentionally collapses whitespace for display rules.
                            const escaped = value.replace(/</g, '&lt;').replace(/ /g, '\uE000');
                            const span = Jsoup.parse('<span>X' + escaped + 'Y</span>').selectFirst('span');
                            return span ? span.text().slice(1, -1).replace(/\uE000/g, ' ') : value;
                        };
                    }
                    if (typeof globalThis.org.jsoup.Jsoup.parse !== 'function') {
                        globalThis.org.jsoup.Jsoup.parse = function(html, baseUri) {
                            let source = String(html == null ? '' : html);
                            const identity = { nodes: new NativeMap(), next: new NativeMap(), prev: new NativeMap(), dirty: new WeakSet(), revision: 0 };
                            const invalidate = () => {
                                identity.nodes.clear();
                                identity.next.clear();
                                identity.prev.clear();
                                identity.revision++;
                            };
                            let base = String(baseUri == null ? '' : baseUri);
                            // Jsoup HtmlTreeBuilder uses the first resolvable base href
                            // and keeps that document base after later DOM removal.
                            for (const element of java.getElements('base[href]', source, true)) {
                                const resolved = java.__jsoupAbsUrl(element.attr('href'), base);
                                if (resolved !== '') {
                                    base = resolved;
                                    break;
                                }
                            }
                            const escapeHtml = value => String(value == null ? '' : value)
                                .replace(/&/g, '&amp;').replace(/</g, '&lt;')
                                .replace(/>/g, '&gt;');
                            const createElement = tag => {
                                tag = String(tag);
                                if (!/^[a-z][a-z0-9:-]*$/i.test(tag)) throw new TypeError('invalid tag name');
                                const attributes = Object.create(null);
                                let children = '';
                                return wrapStringMethods({
                                    attr(name, value) {
                                        name = String(name);
                                        if (arguments.length === 1) return attributes[name] || '';
                                        if (!/^[a-z_:][a-z0-9_:.-]*$/i.test(name)) throw new TypeError('invalid attribute name');
                                        attributes[name] = String(value);
                                        return this;
                                    },
                                    id(value) {
                                        return arguments.length ? this.attr('id', value) : this.attr('id');
                                    },
                                    className() { return this.attr('class'); },
                                    appendChild(child) {
                                        if (!child || typeof child.outerHtml !== 'function') throw new TypeError('invalid child');
                                        children += child.outerHtml();
                                        return this;
                                    },
                                    appendText(value) { children += escapeHtml(value); return this; },
                                    text(value) {
                                        if (arguments.length === 0) return globalThis.org.jsoup.Jsoup.parse(children).text();
                                        children = escapeHtml(value);
                                        return this;
                                    },
                                    textNodes() { return java.__jsoupTextNodeList([this]); },
                                    hasText() { return String(this.text()).trim() !== ''; },
                                    elementSiblingIndex() { return 0; },
                                    siblingElements() { return deriveCollection([], null, null); },
                                    nextElementSiblings() { return deriveCollection([], null, null); },
                                    previousElementSiblings() { return deriveCollection([], null, null); },
                                    tagName() { return tag.toLowerCase(); },
                                    nodeName() { return this.tagName(); },
                                    equals(other) { return this === other; },
                                    toJSON() {
                                        return { __readerHtmlElement: true, outerHtml: this.outerHtml() };
                                    },
                                    html(value) {
                                        if (arguments.length) { children = String(value); return this; }
                                        return children;
                                    },
                                    outerHtml() {
                                        const attrs = Object.keys(attributes).map(name =>
                                            ' ' + name + '="' + escapeHtml(attributes[name]).replace(/"/g, '&quot;') + '"').join('');
                                        return '<' + tag + attrs + '>' +
                                            (/^(?:img|br|hr|input|meta|link)$/i.test(tag)
                                                ? '' : children + '</' + tag + '>');
                                    }
                                }, elementStringMethods);
                            };
                            // Jsoup accepts unquoted dotted attribute values, e.g.
                            // a[href*=.html], which a CSS parser requires to be quoted.
                            const normalizeSelector = selector => String(selector).replace(
                                /\[([a-z_][\w:-]*\s*[*^$~|]?=)\s*(\.[\w.-]+)(\s*)\]/gi,
                                '[$1"$2"$3]');
                            const plainSelector = /^(?:[a-z][\w-]*|\*|[.#][\w-]+)(?:[.#][\w-]+)*(?:\s*,\s*(?:[a-z][\w-]*|\*|[.#][\w-]+)(?:[.#][\w-]+)*)*$/i;
                            const stringList = values => {
                                const position = index => {
                                    if (!Number.isInteger(index) || index < 0 || index >= values.length)
                                        throw new RangeError('list index out of bounds');
                                    return index;
                                };
                                values.size = function() {
                                    if (arguments.length) throw new TypeError('list.size takes no arguments');
                                    return values.length;
                                };
                                values.get = function(index) {
                                    if (arguments.length !== 1) throw new TypeError('list.get requires one index');
                                    return values[position(index)];
                                };
                                values.set = function(index, value) {
                                    if (arguments.length !== 2) throw new TypeError('list.set requires index and value');
                                    const i = position(index), previous = values[i];
                                    values[i] = value;
                                    return previous;
                                };
                                values.add = function(value) {
                                    if (arguments.length !== 1) throw new TypeError('unsupported list.add overload');
                                    values.push(value);
                                    return true;
                                };
                                values.toString = () => '[' + values.join(', ') + ']';
                                return values;
                            };
                            const removeAt = (items, index) => {
                                const position = Number(index);
                                if (!Number.isInteger(position) || position < 0 || position >= items.length)
                                    throw new RangeError('element index out of bounds');
                                return items.splice(position, 1)[0];
                            };
                            const decorate = (items, parent, scope) => {
                                let replacementCursor = 0;
                                for (let i = 0; i < items.length; i++) {
                                    const item = items[i];
                                    const nodeId = scope && item.__readerHtmlNodeId;
                                    if (nodeId && scope.nodes.has(nodeId)) {
                                        items[i] = scope.nodes.get(nodeId);
                                        continue;
                                    }
                                    item.equals = other => item === other;
                                    if (nodeId) {
                                        scope.nodes.set(nodeId, item);
                                        const revision = scope.revision;
                                        item.nextElementSibling = () => {
                                            if (revision !== scope.revision) return null;
                                            if (scope.next.has(nodeId)) return scope.next.get(nodeId);
                                            const siblings = decorate(
                                                globalThis.__wrapReaderElements(JSON.parse(
                                                    java.__jsoupSiblings(source, nodeId))), parent, scope);
                                            let previous = item;
                                            for (const sibling of siblings) {
                                                scope.next.set(previous.__readerHtmlNodeId, sibling);
                                                previous = sibling;
                                            }
                                            scope.next.set(previous.__readerHtmlNodeId, null);
                                            return siblings[0] || null;
                                        };
                                        item.previousElementSibling = () => {
                                            if (revision !== scope.revision) return null;
                                            if (scope.prev.has(nodeId)) return scope.prev.get(nodeId);
                                            const siblings = decorate(
                                                globalThis.__wrapReaderElements(JSON.parse(
                                                    java.__jsoupSiblings(source, nodeId, true))), parent, scope);
                                            let next = item;
                                            for (const sibling of siblings) {
                                                scope.prev.set(next.__readerHtmlNodeId, sibling);
                                                next = sibling;
                                            }
                                            scope.prev.set(next.__readerHtmlNodeId, null);
                                            return siblings[0] || null;
                                        };
                                        const elementSiblings = next => {
                                            const siblings = [];
                                            let sibling = item;
                                            while ((sibling = next
                                                    ? sibling.nextElementSibling()
                                                    : sibling.previousElementSibling())) siblings.push(sibling);
                                            return deriveCollection(siblings, parent, scope);
                                        };
                                        item.nextElementSiblings = () => elementSiblings(true);
                                        item.previousElementSiblings = () => elementSiblings(false);
                                        item.elementSiblingIndex = () => {
                                            let index = 0, sibling = item;
                                            while ((sibling = sibling.previousElementSibling())) index++;
                                            return index;
                                        };
                                        item.siblingElements = () => {
                                            const before = [], after = [];
                                            let sibling = item;
                                            while ((sibling = sibling.previousElementSibling())) before.push(sibling);
                                            sibling = item;
                                            while ((sibling = sibling.nextElementSibling())) after.push(sibling);
                                            return deriveCollection(before.reverse().concat(after), parent, scope);
                                        };
                                        const ancestorIds = item.__readerHtmlAncestors || [];
                                        item.parents = () => {
                                            let loaded;
                                            const load = () => {
                                                if (revision !== scope.revision) return decorate([], null, scope);
                                                if (!loaded) loaded = decorate(globalThis.__wrapReaderElements(
                                                    JSON.parse(java.__jsoupAncestors(source, nodeId))), null, scope);
                                                return loaded;
                                            };
                                            return {
                                                contains(other) {
                                                    const id = other && other.__readerHtmlNodeId;
                                                    return revision === scope.revision && ancestorIds.includes(id)
                                                        && scope.nodes.get(id) === other;
                                                },
                                                size() { return revision === scope.revision ? ancestorIds.length : 0; },
                                                isEmpty() { return this.size() === 0; },
                                                get(index) { return load().get(index); },
                                                first() { return load().first(); },
                                                last() { return load().last(); },
                                                toArray() { return load().toArray(); },
                                                [Symbol.iterator]() { return load()[Symbol.iterator](); }
                                            };
                                        };
                                        item.parent = () => {
                                            if (revision !== scope.revision) return null;
                                            const parentId = ancestorIds[0];
                                            if (!parentId) return null;
                                            if (!scope.nodes.has(parentId)) {
                                                const ids = [];
                                                for (const node of scope.nodes.values()) {
                                                    const id = node.__readerHtmlAncestors?.[0];
                                                    if (id && !scope.nodes.has(id)) ids.push(id);
                                                }
                                                decorate(globalThis.__wrapReaderElements(JSON.parse(
                                                    java.__jsoupParents(source, JSON.stringify(ids)))), null, scope);
                                            }
                                            return scope.nodes.get(parentId) || null;
                                        };
                                    }
                                    const attr = item.attr.bind(item);
                                    const hasAttr = item.hasAttr.bind(item);
                                    const select = item.select.bind(item);
                                    const html = item.html.bind(item);
                                    const outerHtml = item.outerHtml.bind(item);
                                    let innerHtml;
                                    let changedAttrs;
                                    const originalToJSON = item.toJSON;
                                    item.toJSON = () => {
                                        if (innerHtml === undefined && !changedAttrs) {
                                            return originalToJSON ? originalToJSON.call(item) : item;
                                        }
                                        // A mutated Jsoup element is a detached HTML carrier.
                                        // Never serialize the stale original node descriptor.
                                        return {
                                            __readerHtmlElement: true,
                                            outerHtml: item.outerHtml(),
                                        };
                                    };
                                    item.html = function(value) {
                                        if (arguments.length) {
                                            innerHtml = String(value);
                                            if (scope) scope.dirty.add(item);
                                            return item;
                                        }
                                        return innerHtml === undefined ? html() : innerHtml;
                                    };
                                    item.outerHtml = () => {
                                        const original = outerHtml();
                                        if (innerHtml === undefined && !changedAttrs) return original;
                                        const opening = /^<([a-z][\w:-]*)\b(?:[^>"']|"[^"]*"|'[^']*')*>/i.exec(original);
                                        if (!opening) return original;
                                        let start = opening[0];
                                        for (const [name, value] of changedAttrs || []) {
                                            const escaped = escapeHtml(value).replace(/"/g, '&quot;');
                                            const key = name.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
                                            const pattern = new RegExp('\\s' + key +
                                                '\\s*=\\s*(?:"[^"]*"|\\x27[^\\x27]*\\x27|[^\\s>]+)', 'i');
                                            const replacement = ' ' + name + '="' + escaped + '"';
                                            start = pattern.test(start)
                                                ? start.replace(pattern, replacement)
                                                : start.slice(0, -1) + replacement + '>';
                                        }
                                        const closing = new RegExp('</' + opening[1] + '\\s*>$', 'i').exec(original);
                                        return closing ? start + (innerHtml === undefined ? html() : innerHtml) + closing[0] : start;
                                    };
                                    item.attr = function(name, value) {
                                        name = String(name);
                                        if (arguments.length > 1) {
                                            if (!/^[a-z_:][a-z0-9_:.-]*$/i.test(name)) throw new TypeError('invalid attribute name');
                                            if (!changedAttrs) changedAttrs = new NativeMap();
                                            changedAttrs.set(name, String(value));
                                            if (scope) scope.dirty.add(item);
                                            return item;
                                        }
                                        if (name.startsWith('abs:')) {
                                            const key = name.slice(4);
                                            return item.hasAttr(key) ? java.__jsoupAbsUrl(item.attr(key), base) : '';
                                        }
                                        return changedAttrs && changedAttrs.has(name) ? changedAttrs.get(name) : attr(name);
                                    };
                                    item.hasAttr = name => {
                                        name = String(name);
                                        return name.startsWith('abs:') ? String(item.attr(name)) !== ''
                                            : (changedAttrs && changedAttrs.has(name)) || hasAttr(name);
                                    };
                                    item.id = function(value) {
                                        return arguments.length ? item.attr('id', value) : item.attr('id');
                                    };
                                    item.className = () => item.attr('class');
                                    item.nodeName = () => item.tagName();
                                    item.hasText = () => String(item.text()).trim() !== '';
                                    item.is = selector => {
                                        const rule = normalizeSelector(selector);
                                        if (scope && nodeId && scope.nodes.get(nodeId) === item
                                                && innerHtml === undefined && !changedAttrs)
                                            return java.getElements(rule, source, true, true)
                                                .some(node => node.__readerHtmlNodeId === nodeId);
                                        const markup = String(item.outerHtml());
                                        return java.getElements(rule, markup, true)
                                            .some(node => String(node.outerHtml()) === markup);
                                    };
                                    item.hasClass = name => {
                                        const target = String(name).toLowerCase();
                                        return String(item.attr('class')).split(/\s+/)
                                            .some(value => value.toLowerCase() === target);
                                    };
                                    const originalText = item.text.bind(item);
                                    item.text = function(value) {
                                        if (arguments.length > 0) {
                                            innerHtml = escapeHtml(value);
                                            if (scope) scope.dirty.add(item);
                                            return item;
                                        }
                                        if (innerHtml === undefined) return originalText();
                                        const body = java.getElements('body', innerHtml, true).first();
                                        return body ? body.text() : '';
                                    };
                                    item.textNodes = () => java.__jsoupTextNodeList([item]);
                                    item.clone = () => {
                                        // Copy into an independent Jsoup document: removing
                                        // badges from a clone must not mutate its original.
                                        const markup = item.outerHtml();
                                        const match = /^<([a-z][\w:-]*)\b/i.exec(markup);
                                        if (!match) throw new Error('invalid jsoup clone target');
                                        const copy = globalThis.org.jsoup.Jsoup.parse(markup, base).selectFirst(match[1]);
                                        if (!copy) throw new Error('failed to clone jsoup element');
                                        return copy;
                                    };
                                    // Jsoup data() reads raw DataNode content (script/style),
                                    // not the normalized visible text of ordinary elements.
                                    item.data = () => /^(?:script|style)$/i.test(item.tagName())
                                        ? globalThis.org.jsoup.parser.Parser.unescapeEntities(item.html(), false) : '';
                                    item.ownText = () => {
                                        const match = /^<([a-z][\w:-]*)\b/i.exec(item.outerHtml());
                                        if (!match) return '';
                                        const tag = match[1];
                                        // Reuse Legado's existing @ownText selector. Read the
                                        // current inner HTML, including nested DOM removals.
                                        return java.getString(tag + '@ownText',
                                            '<' + tag + '>' + item.html() + '</' + tag + '>')
                                            .replace(/\s+/g, ' ').trim();
                                    };
                                    if (parent) {
                                        const original = item.outerHtml();
                                        let replaced = false;
                                        const replaceMarkup = output => {
                                            if (replaced) throw new Error('jsoup replacement target is detached');
                                            const html = parent.read();
                                            const index = html.indexOf(original, replacementCursor);
                                            if (index < 0) throw new Error('jsoup replacement target is unavailable');
                                            parent.write(html.slice(0, index) + output + html.slice(index + original.length));
                                            replaced = true;
                                            replacementCursor = index + output.length;
                                            return item;
                                        };
                                        item.replaceWith = replacement => {
                                            if (!replacement || typeof replacement.outerHtml !== 'function')
                                                throw new TypeError('invalid replacement');
                                            return replaceMarkup(replacement.outerHtml());
                                        };
                                        item.remove = () => replaceMarkup('');
                                    }
                                    item.select = selector => {
                                        const rule = normalizeSelector(selector);
                                        const selected = decorate(innerHtml === undefined
                                            ? select(rule)
                                            : java.getElements(rule, innerHtml, true), {
                                                read: () => item.html(),
                                                write: html => { item.html(html); }
                                            });
                                        selected.remove = function(index) {
                                            if (arguments.length) return removeAt(selected, index);
                                            const updated = java.__jsoupRemove(item.html(), rule);
                                            if (updated == null) throw new Error('invalid jsoup remove selector');
                                            const body = java.getElements('body', updated, true).first();
                                            item.html(body ? body.html() : '');
                                            return selected;
                                        };
                                        return selected;
                                    };
                                    item.selectFirst = selector => item.select(selector).first();
                                    item.getElementsByTag = name => {
                                        const tag = String(name);
                                        // Query only the supplied fragment, not the parser's
                                        // synthetic head/body ancestors (notably for '*').
                                        const matches = item.select('body > ' + tag + ', body > * ' + tag);
                                        if (tag === '*' || String(item.tagName()).toLowerCase() === tag.toLowerCase()) {
                                            if (innerHtml === undefined && matches.length) matches[0] = item;
                                            else matches.unshift(item);
                                        }
                                        return matches;
                                    };
                                    item.getElementsByClass = name => {
                                        const className = String(name);
                                        const matches = item.select('[class~=' + JSON.stringify(className) + ' i]');
                                        if (item.hasClass(className)) {
                                            if (innerHtml === undefined && matches.length) matches[0] = item;
                                            else matches.unshift(item);
                                        }
                                        return matches;
                                    };
                                    const collectAttributes = predicate => {
                                        const matches = item.getElementsByTag('*');
                                        for (let i = matches.length - 1; i >= 0; i--)
                                            if (!predicate(matches[i])) matches.splice(i, 1);
                                        return matches;
                                    };
                                    item.getElementsByAttribute = name => {
                                        const key = String(name).trim().toLowerCase();
                                        return collectAttributes(node => node.hasAttr(key));
                                    };
                                    item.getElementsByAttributeValue = (name, value) => {
                                        const key = String(name).trim().toLowerCase();
                                        const expected = String(value).trim().toLowerCase();
                                        return collectAttributes(node => node.hasAttr(key)
                                            && String(node.attr(key)).trim().toLowerCase() === expected);
                                    };
                                    item.children = () => {
                                        // Reparse only the current inner fragment: body > * selects
                                        // immediate element children, not nested descendants.
                                        const rule = 'body > *';
                                        const selected = decorate(java.getElements(rule, item.html(), true), {
                                            read: () => item.html(),
                                            write: html => { item.html(html); }
                                        });
                                        selected.remove = function(index) {
                                            if (arguments.length) return removeAt(selected, index);
                                            const updated = java.__jsoupRemove(item.html(), rule);
                                            if (updated == null) throw new Error('invalid jsoup remove selector');
                                            const body = java.getElements('body', updated, true).first();
                                            item.html(body ? body.html() : '');
                                            return selected;
                                        };
                                        return selected;
                                    };
                                    item.child = index => item.children().get(Number(index));
                                    item.absUrl = name => item.attr('abs:' + String(name));
                                    wrapStringMethods(item, elementStringMethods);
                                    item.baseUri = () => base;
                                }
                                return decorateCollection(items, parent, scope);
                            };
                            const decorateCollection = (items, parent, scope) => {
                                Object.defineProperties(items, {
                                    outerHtml: { value: elementsOuterHtml },
                                    toString: { value: elementsOuterHtml }
                                });
                                items.attr = function(name, value) {
                                    if (arguments.length > 1) {
                                        for (const item of items) item.attr(name, value);
                                        return items;
                                    }
                                    const item = items.find(item => item.hasAttr(name));
                                    return item ? item.attr(name) : '';
                                };
                                items.text = function(value) {
                                    if (arguments.length) {
                                        for (const item of items) item.text(value);
                                        return items;
                                    }
                                    return items.map(item => item.text()).join(' ');
                                };
                                items.textNodes = () => java.__jsoupTextNodeList(items);
                                items.eachText = () => stringList(items.map(item => item.text())
                                    .filter(value => String(value).trim() !== ''));
                                items.eachAttr = name => stringList(items.filter(item => item.hasAttr(name))
                                    .map(item => item.attr(name)));
                                // jsoup Elements.html(): inner HTML of every match,
                                // separated by a newline (not outerHTML).
                                items.html = function(value) {
                                    if (arguments.length) {
                                        for (const item of items) item.html(value);
                                        return items;
                                    }
                                    return items.map(item => item.html()).join('\n');
                                };
                                items.isEmpty = () => items.length === 0;
                                items.hasClass = name => items.some(item => item.hasClass(name));
                                items.hasAttr = name => items.some(item => item.hasAttr(name));
                                items.contains = element => items.some(item => item === element);
                                items.subList = (from, to) => {
                                    const start = Number(from), end = Number(to);
                                    if (!Number.isInteger(start) || !Number.isInteger(end)
                                            || start < 0 || end < start || end > items.length)
                                        throw new RangeError('invalid subList range');
                                    return { clear() { items.splice(start, end - start); } };
                                };
                                items.last = () => items.length ? items[items.length - 1] : null;
                                const derived = nodes => deriveCollection(nodes, parent, scope);
                                items.eq = index => {
                                    if (Number.isInteger(index) && index < 0) throw new RangeError('element index out of bounds');
                                    return derived(Number.isInteger(index) && index < items.length
                                        ? [items[index]] : []);
                                };
                                const live = item => scope && item.__readerHtmlNodeId
                                    && scope.nodes.get(item.__readerHtmlNodeId) === item
                                    && !scope.dirty.has(item);
                                items.select = selector => {
                                    const rule = normalizeSelector(selector);
                                    // Plain selectors can resolve all roots against one document,
                                    // preserving real node IDs even when roots overlap.
                                    if (scope && items.length > 1 && plainSelector.test(rule)) {
                                        const roots = new Set(items.map(item => item.__readerHtmlNodeId));
                                        const overlapping = roots.size < items.length || items.some(item =>
                                            item.__readerHtmlAncestors?.some(id => roots.has(id)));
                                        if (overlapping && items.every(live)) {
                                            const candidates = decorate(java.getElements(rule, source, true, true), parent, scope);
                                            const matches = [], seen = new Set();
                                            for (const item of items) {
                                                const rootId = item.__readerHtmlNodeId;
                                                for (const node of candidates) {
                                                    const id = node.__readerHtmlNodeId;
                                                    if (!seen.has(id) && (id === rootId
                                                            || node.__readerHtmlAncestors?.includes(rootId))) {
                                                        seen.add(id);
                                                        matches.push(node);
                                                    }
                                                }
                                            }
                                            return derived(matches);
                                        }
                                    }
                                    const matches = [], seen = new Set();
                                    for (const item of items) {
                                        for (const node of item.select(rule)) {
                                            if (!seen.has(node)) {
                                                seen.add(node);
                                                matches.push(node);
                                            }
                                        }
                                    }
                                    return derived(matches);
                                };
                                items.selectFirst = selector => {
                                    const first = items.select(selector).first();
                                    if (!first) return null;
                                    // Preserve the first root if it is itself the first match.
                                    if (items.length && items[0].is(selector)) return items[0];
                                    // Never equate distinct nodes based on identical outer HTML.
                                    const id = first.__readerHtmlNodeId;
                                    return id ? items.find(item => item.__readerHtmlNodeId === id) || first : first;
                                };
                                items.next = function(selector) {
                                    const siblings = [];
                                    for (const item of items) {
                                        const next = item.nextElementSibling?.();
                                        if (next && (arguments.length === 0 || next.is(selector)))
                                            siblings.push(next);
                                    }
                                    return derived(siblings);
                                };
                                items.prev = function(selector) {
                                    const siblings = [];
                                    for (const item of items) {
                                        const prev = item.previousElementSibling?.();
                                        if (prev && (arguments.length === 0 || prev.is(selector)))
                                            siblings.push(prev);
                                    }
                                    return derived(siblings);
                                };
                                const allSiblings = (method, selector) => {
                                    const siblings = [];
                                    for (const item of items) {
                                        if (typeof item[method] !== 'function') continue;
                                        for (const sibling of item[method]()) {
                                            if (selector == null || sibling.is(selector)) siblings.push(sibling);
                                        }
                                    }
                                    return derived(siblings);
                                };
                                items.nextAll = selector => allSiblings('nextElementSiblings', selector);
                                items.prevAll = selector => allSiblings('previousElementSiblings', selector);
                                items.parents = () => {
                                    const ancestors = [], seen = new Set();
                                    for (const item of items) {
                                        if (typeof item.parents !== 'function') continue;
                                        for (const ancestor of item.parents()) {
                                            if (!seen.has(ancestor)) {
                                                seen.add(ancestor);
                                                ancestors.push(ancestor);
                                            }
                                        }
                                    }
                                    return derived(ancestors);
                                };
                                const matchesSelector = selector => {
                                    const rule = normalizeSelector(selector);
                                    const scoped = scope && items.some(live);
                                    const ids = scoped ? new Set(java.getElements(rule, source, true, true)
                                        .map(node => node.__readerHtmlNodeId)) : null;
                                    return item => live(item) ? ids.has(item.__readerHtmlNodeId) : item.is(rule);
                                };
                                items.is = selector => items.length > 0 && items.some(matchesSelector(selector));
                                items.not = selector => {
                                    const matches = matchesSelector(selector);
                                    return derived(items.filter(item => !matches(item)));
                                };
                                for (const method of ['select', 'selectFirst', 'next', 'prev', 'nextAll', 'prevAll', 'parents', 'not', 'is', 'hasAttr'])
                                    Object.defineProperty(items, method, { enumerable: false });
                                // Preserve existing Elements getter values; only new setter overloads change behavior.
                                return items;
                            };
                            const deriveCollection = (nodes, parent, scope) => {
                                const result = decorateCollection(globalThis.__wrapReaderElements(nodes, true), parent, scope);
                                Object.defineProperty(result, 'remove', { value: function(index) {
                                    if (arguments.length) return removeAt(result, index);
                                    for (const node of result) node.remove();
                                    return result;
                                } });
                                return result;
                            };
                            return wrapStringMethods({
                                createElement,
                                baseUri() { return base; },
                                html() { return source; },
                                title() {
                                    const title = this.selectFirst('title');
                                    return title ? title.text() : '';
                                },
                                body() { return this.selectFirst('body'); },
                                text() {
                                    const body = this.body();
                                    return body ? body.text().replace(/\s+/g, ' ').trim() : '';
                                },
                                selectFirst(selector) { return this.select(selector).first(); },
                                getElementsByTag(name) { return this.select(String(name)); },
                                getElementsByClass(name) {
                                    return this.select('[class~=' + JSON.stringify(String(name)) + ' i]');
                                },
                                select(selector) {
                                    const rule = normalizeSelector(selector);
                                    const items = decorate(globalThis.java.getElements(rule, source, true, true), {
                                        read: () => source,
                                        write: html => { source = html; invalidate(); }
                                    }, identity);
                                    items.remove = function(index) {
                                        if (arguments.length) return removeAt(items, index);
                                        const updated = globalThis.java.__jsoupRemove(source, rule);
                                        if (updated == null) throw new Error('invalid jsoup remove selector');
                                        source = updated;
                                        invalidate();
                                        return items;
                                    };
                                    return items;
                                }
                            }, ['baseUri', 'html', 'title', 'text']);
                        };
                    }
                    if (typeof globalThis.org.jsoup.nodes.Element !== 'function') {
                        let createElement;
                        globalThis.org.jsoup.nodes.Element = function(tag) {
                            if (!createElement) createElement = globalThis.org.jsoup.Jsoup.parse('').createElement;
                            return createElement(tag);
                        };
                    }
                    if (typeof globalThis.org.jsoup.Jsoup.parseBodyFragment !== 'function') {
                        // This adapter's parse() already accepts HTML fragments and
                        // produces a Document with a body() element.
                        globalThis.org.jsoup.Jsoup.parseBodyFragment = function(html, baseUri) {
                            return globalThis.org.jsoup.Jsoup.parse(html, baseUri);
                        };
                    }
                    globalThis.org.jsoup.Connection = asObject(globalThis.org.jsoup.Connection);
                    globalThis.org.jsoup.Connection.Method = Object.freeze({
                        GET: 'GET', POST: 'POST', HEAD: 'HEAD'
                    });
                    Object.defineProperty(globalThis.org.jsoup.Connection, '__javaName', { value: 'Connection' });
                    Object.defineProperty(globalThis.org.jsoup.Jsoup, '__javaName', { value: 'Jsoup' });
                    if (typeof globalThis.org.jsoup.Jsoup.connect !== 'function') {
                        globalThis.org.jsoup.Jsoup.connect = function(url) {
                            const target = String(url);
                            let method = 'GET', headers = {}, body = '', timeout;
                            let follow = true;
                            const connection = {
                                method(value) {
                                    method = String(value);
                                    if (!['GET', 'HEAD', 'POST'].includes(method))
                                        throw new TypeError('unsupported Jsoup request method');
                                    return this;
                                },
                                ignoreContentType() { return this; },
                                followRedirects(value) { follow = !!value; return this; },
                                headers(value) {
                                    headers = value instanceof NativeMap ? Object.fromEntries(value)
                                        : Object.assign({}, value);
                                    return this;
                                },
                                requestBody(value) { body = String(value); return this; },
                                timeout(value) { timeout = value; return this; },
                                execute() {
                                    // Host java.get intentionally does not follow redirects.
                                    let current = target;
                                    for (let hop = 0; hop < 6; hop++) {
                                        const response = method === 'HEAD'
                                            ? java.head(current, headers, timeout)
                                            : method === 'POST'
                                                ? java.post(current, body, headers, timeout)
                                                : java.get(current, headers, timeout);
                                        const code = response.statusCode();
                                        if (follow && [301, 302, 303, 307, 308].includes(code)) {
                                            const location = response.header('location');
                                            current = location && java.__jsoupAbsUrl(String(location), current);
                                            if (!current || !/^https?:\/\//i.test(current))
                                                throw new Error('invalid Jsoup redirect');
                                            if (code === 303 || ((code === 301 || code === 302) && method === 'POST'))
                                                method = 'GET';
                                            continue;
                                        }
                                        if (code === 0 || code >= 400)
                                            throw new Error('Jsoup HTTP status: ' + code);
                                        return response;
                                    }
                                    throw new Error('too many Jsoup redirects');
                                },
                                get() {
                                    const response = this.method('GET').execute();
                                    const document = response.parse();
                                    const markup = response.body();
                                    fetchedDocuments.set(document, markup);
                                    document.toString = () => markup;
                                    return document;
                                }
                            };
                            return connection;
                        };
                    }
                    wrapStringMethods(globalThis.org.jsoup.parser.Parser, ['unescapeEntities']);
                })();