(function() {
                    const asObject = value => value && (typeof value === 'object' || typeof value === 'function')
                        ? value : {};
                    globalThis.org = asObject(globalThis.org);
                    globalThis.org.jsoup = asObject(globalThis.org.jsoup);
                    globalThis.org.jsoup.Jsoup = asObject(globalThis.org.jsoup.Jsoup);
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
                                return {
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
                                    html() { return children; },
                                    outerHtml() {
                                        const attrs = Object.keys(attributes).map(name =>
                                            ' ' + name + '="' + escapeHtml(attributes[name]).replace(/"/g, '&quot;') + '"').join('');
                                        return '<' + tag + attrs + '>' +
                                            (/^(?:img|br|hr|input|meta|link)$/i.test(tag)
                                                ? '' : children + '</' + tag + '>');
                                    }
                                };
                            };
                            // Jsoup accepts unquoted dotted attribute values, e.g.
                            // a[href*=.html], which a CSS parser requires to be quoted.
                            const normalizeSelector = selector => String(selector).replace(
                                /\[([a-z_][\w:-]*\s*[*^$~|]?=)\s*(\.[\w.-]+)(\s*)\]/gi,
                                '[$1"$2"$3]');
                            const decorate = (items, parent) => {
                                let replacementCursor = 0;
                                for (const item of items) {
                                    const attr = item.attr.bind(item);
                                    const hasAttr = item.hasAttr.bind(item);
                                    const select = item.select.bind(item);
                                    const html = item.html.bind(item);
                                    const outerHtml = item.outerHtml.bind(item);
                                    let innerHtml;
                                    item.html = () => innerHtml === undefined ? html() : innerHtml;
                                    item.outerHtml = () => {
                                        const original = outerHtml();
                                        if (innerHtml === undefined) return original;
                                        // Retain the original start/end tags, including attributes
                                        // containing '>', but serialize the current child markup.
                                        const opening = /^<([a-z][\w:-]*)\b(?:[^>"']|"[^"]*"|'[^']*')*>/i.exec(original);
                                        if (!opening) return original;
                                        const closing = new RegExp('</' + opening[1] + '\\s*>$', 'i').exec(original);
                                        return closing ? opening[0] + innerHtml + closing[0] : original;
                                    };
                                    item.attr = name => {
                                        name = String(name);
                                        if (!name.startsWith('abs:')) return attr(name);
                                        const key = name.slice(4);
                                        return hasAttr(key) ? java.__jsoupAbsUrl(attr(key), base) : '';
                                    };
                                    item.hasAttr = name => {
                                        name = String(name);
                                        return name.startsWith('abs:') ? item.attr(name) !== '' : hasAttr(name);
                                    };
                                    const originalText = item.text.bind(item);
                                    item.text = () => {
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
                                    item.absUrl = name => item.attr('abs:' + String(name));
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
                                return items;
                            };
                            return {
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
                                    const items = decorate(globalThis.java.getElements(rule, source, true), {
                                        read: () => source,
                                        write: html => { source = html; }
                                    });
                                    items.remove = function() {
                                        const updated = globalThis.java.__jsoupRemove(source, rule);
                                        if (updated == null) throw new Error('invalid jsoup remove selector');
                                        source = updated;
                                        return items;
                                    };
                                    return items;
                                }
                            };
                        };
                    }
                    if (typeof globalThis.org.jsoup.Jsoup.parseBodyFragment !== 'function') {
                        // This adapter's parse() already accepts HTML fragments and
                        // produces a Document with a body() element.
                        globalThis.org.jsoup.Jsoup.parseBodyFragment = function(html, baseUri) {
                            return globalThis.org.jsoup.Jsoup.parse(html, baseUri);
                        };
                    }
                })();