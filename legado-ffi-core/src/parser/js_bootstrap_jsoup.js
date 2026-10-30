(function() {
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
                        'data', 'attr', 'absUrl', 'tagName'];
                    const asObject = value => value && (typeof value === 'object' || typeof value === 'function')
                        ? value : {};
                    globalThis.org = asObject(globalThis.org);
                    globalThis.org.jsoup = asObject(globalThis.org.jsoup);
                    globalThis.org.jsoup.Jsoup = asObject(globalThis.org.jsoup.Jsoup);
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
                            const escaped = value.replace(/</g, '&lt;');
                            const span = Jsoup.parse('<span>X' + escaped + 'Y</span>').selectFirst('span');
                            return span ? span.text().slice(1, -1) : value;
                        };
                    }
                    if (typeof globalThis.org.jsoup.Jsoup.parse !== 'function') {
                        globalThis.org.jsoup.Jsoup.parse = function(html, baseUri) {
                            let source = String(html == null ? '' : html);
                            const identity = { nodes: new Map(), next: new Map(), revision: 0 };
                            const invalidate = () => {
                                identity.nodes.clear();
                                identity.next.clear();
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
                                    tagName() { return tag.toLowerCase(); },
                                    equals(other) { return this === other; },
                                    toJSON() {
                                        return { __readerHtmlElement: true, outerHtml: this.outerHtml() };
                                    },
                                    html() { return children; },
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
                                    item.html = () => innerHtml === undefined ? html() : innerHtml;
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
                                            if (!changedAttrs) changedAttrs = new Map();
                                            changedAttrs.set(name, String(value));
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
                                    const originalText = item.text.bind(item);
                                    item.text = function(value) {
                                        if (arguments.length > 0) {
                                            innerHtml = escapeHtml(value);
                                            return item;
                                        }
                                        if (innerHtml === undefined) return originalText();
                                        const body = java.getElements('body', innerHtml, true).first();
                                        return body ? body.text() : '';
                                    };
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
                                        ? item.html() : '';
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
                                                write: html => { innerHtml = html; }
                                            });
                                        selected.remove = () => {
                                            const updated = java.__jsoupRemove(item.html(), rule);
                                            if (updated == null) throw new Error('invalid jsoup remove selector');
                                            const body = java.getElements('body', updated, true).first();
                                            innerHtml = body ? body.html() : '';
                                            return selected;
                                        };
                                        return selected;
                                    };
                                    item.selectFirst = selector => item.select(selector).first();
                                    item.children = () => {
                                        // Reparse only the current inner fragment: body > * selects
                                        // immediate element children, not nested descendants.
                                        const rule = 'body > *';
                                        const selected = decorate(java.getElements(rule, item.html(), true), {
                                            read: () => item.html(),
                                            write: html => { innerHtml = html; }
                                        });
                                        selected.remove = () => {
                                            const updated = java.__jsoupRemove(item.html(), rule);
                                            if (updated == null) throw new Error('invalid jsoup remove selector');
                                            const body = java.getElements('body', updated, true).first();
                                            innerHtml = body ? body.html() : '';
                                            return selected;
                                        };
                                        return selected;
                                    };
                                    item.child = index => item.children().get(Number(index));
                                    item.absUrl = name => item.attr('abs:' + String(name));
                                    wrapStringMethods(item, elementStringMethods);
                                    item.baseUri = () => base;
                                }
                                items.attr = name => {
                                    const item = items.find(item => item.hasAttr(name));
                                    return item ? item.attr(name) : '';
                                };
                                items.text = () => items.map(item => item.text()).join(' ');
                                // jsoup Elements.html(): inner HTML of every match,
                                // separated by a newline (not outerHTML).
                                items.html = () => items.map(item => item.html()).join('\n');
                                items.isEmpty = () => items.length === 0;
                                items.last = () => items.length ? items[items.length - 1] : null;
                                return wrapStringMethods(items, ['attr', 'text', 'html']);
                            };
                            return wrapStringMethods({
                                createElement,
                                baseUri() { return base; },
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
                                select(selector) {
                                    const rule = normalizeSelector(selector);
                                    const items = decorate(globalThis.java.getElements(rule, source, true, true), {
                                        read: () => source,
                                        write: html => { source = html; invalidate(); }
                                    }, identity);
                                    items.remove = function() {
                                        const updated = globalThis.java.__jsoupRemove(source, rule);
                                        if (updated == null) throw new Error('invalid jsoup remove selector');
                                        source = updated;
                                        invalidate();
                                        return items;
                                    };
                                    return items;
                                }
                            }, ['baseUri', 'title', 'text']);
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
                    wrapStringMethods(globalThis.org.jsoup.parser.Parser, ['unescapeEntities']);
                })();