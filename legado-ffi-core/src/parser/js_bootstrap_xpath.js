if (globalThis.java && globalThis.java.getString) {
                    const _xpathDocuments = new Map();
                    const _xpathDocumentIds = new Map();
                    let _xpathDocumentBytes = 0;
                    const _internXPathDocument = document => {
                        if (_xpathDocumentIds.has(document)) return _xpathDocumentIds.get(document);
                        const bytes = document.length * 2;
                        if (_xpathDocuments.size >= 64 || _xpathDocumentBytes + bytes > 8 * 1024 * 1024) {
                            throw new RangeError('XPath document pool budget exceeded');
                        }
                        const id = _xpathDocuments.size;
                        _xpathDocuments.set(id, document);
                        _xpathDocumentIds.set(document, id);
                        _xpathDocumentBytes += bytes;
                        return id;
                    };
                    const _readerNodeContent = (rule, content, rawCss = false) => {
                        if (!content || typeof content !== 'object' || !('__readerXPathNode' in content)) return content;
                        const xpath = !rawCss && /^\s*(?:@xpath:|\/|\.\/|id\()/i.test(String(rule));
                        if (xpath) {
                            const node = content.__readerXPathNode;
                            const document = node && _xpathDocuments.get(node.documentId);
                            return JSON.stringify({__readerXPathNode: node && {
                                document: document === undefined ? node.document : document,
                                path: node.path, htmlMode: node.htmlMode
                            }});
                        }
                        return typeof content.outerHtml === 'function' ? content.outerHtml() : '';
                    };
                    const _orig_getString = globalThis.java.getString;
                    globalThis.java.getString = function(rule, content, isUrl, unescape) {
                        const r = (rule !== undefined && rule !== null) ? String(rule) : undefined;
                        if (typeof content === 'boolean' && arguments.length === 2) {
                            return _orig_getString(r, undefined, false, content);
                        }
                        content = _readerNodeContent(r, content);
                        if (typeof content === 'object' && content !== null) {
                            try { content = JSON.stringify(content); } catch (e) {}
                        }
                        const c = (content !== undefined && content !== null) ? String(content) : undefined;
                        return _orig_getString(r, c, isUrl, unescape);
                    };
                    const _orig_getStringList = globalThis.java.getStringList;
                    globalThis.java.getStringList = function(rule, content, isUrl) {
                        if (rule == null || String(rule) === '') return null;
                        content = _readerNodeContent(rule, content);
                        if (typeof content === 'object' && content !== null) {
                            try { content = JSON.stringify(content); } catch (e) {}
                        }
                        const r = String(rule);
                        const c = (content !== undefined && content !== null) ? String(content) : undefined;
                        const values = _orig_getStringList(r, c, isUrl);
                        Object.defineProperties(values, {
                            size: { value() { return this.length; } },
                            get: { value(index) {
                                if (!Number.isInteger(index) || index < 0 || index >= this.length) {
                                    throw new RangeError('string list index out of bounds');
                                }
                                return this[index];
                            } }
                        });
                        return values;
                    };
                    const _nativeSetContent = globalThis.java.__setContent;
                    globalThis.java.setContent = function(content, newBaseUrl) {
                        if (content == null) throw new Error('content cannot be null');
                        if (typeof content === 'object') {
                            try { content = JSON.stringify(content); } catch (e) {}
                        }
                        const normalized = String(content);
                        const base = newBaseUrl == null ? undefined : String(newBaseUrl);
                        if (base === undefined) _nativeSetContent(normalized);
                        else _nativeSetContent(normalized, base);
                        if (base !== undefined) {
                            globalThis.baseUrl = base;
                            globalThis.base_url = base;
                        }
                        return globalThis.java;
                    };
                    const _nativeGetElements = globalThis.java.getElements;
                    const _nativeGetElement = globalThis.java.getElement;
                    const _decorateItems = (values, rawCss = false) => {
                        if (!Array.isArray(values)) values = [];
                        const carrier = values.find(item => item && item.__readerXPathNode
                            && typeof item.__readerXPathNode.document === 'string');
                        const documentId = carrier ? _internXPathDocument(carrier.__readerXPathNode.document) : undefined;
                        const items = values.map(item => {
                            if (!item || item.__readerHtmlElement !== true) return item;
                            const attrs = item.attrs || {};
                            const htmlNodeId = item.__readerHtmlNodeId;
                            delete item.__readerHtmlNodeId;
                            const node = item.__readerXPathNode;
                            const context = node ? {
                                documentId: documentId === undefined ? node.documentId : documentId,
                                path: node.path, htmlMode: node.htmlMode
                            } : undefined;
                            const wrapped = {
                                __readerIndex: item.__readerIndex,
                                __readerXPathNode: context,
                                // HTML data survives the JS return boundary without
                                // replacing the public node methods. XPath IDs stay local.
                                ...(context ? {} : { toJSON() { return item; } }),
                                attributes() {
                                    return item.attrList.map(([key, value]) => ({
                                        getKey() { return key; },
                                        getValue() { return value; },
                                        toString() {
                                            const escaped = value.replace(/&/g, '&amp;')
                                                .replace(/</g, '&lt;').replace(/>/g, '&gt;')
                                                .replace(/"/g, '&quot;');
                                            return key + '="' + escaped + '"';
                                        }
                                    }));
                                },
                                attr(name) { return attrs[String(name)] || ''; },
                                hasAttr(name) { return Object.prototype.hasOwnProperty.call(attrs, String(name)); },
                                hasClass(name) {
                                    return String(attrs.class || '').split(/\s+/).includes(String(name));
                                },
                                html() { return item.html || ''; },
                                tagName() {
                                    const opening = /^<([a-z][\w:-]*)\b/i.exec(item.outerHtml || '');
                                    return opening ? opening[1].toLowerCase() : '';
                                },
                                text(value) {
                                    if (arguments.length === 0) return item.text || '';
                                    if (context) return item.text || ''; // Preserve existing XPath behavior.
                                    const outer = item.outerHtml || '';
                                    const opening = /^<([a-z][\w:-]*)\b(?:[^>"']|"[^"]*"|'[^']*')*>/i.exec(outer);
                                    const closing = opening && new RegExp('</' + opening[1] + '\\s*>$', 'i').exec(outer);
                                    if (!closing) return this;
                                    const text = String(value);
                                    const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                                    item.text = text;
                                    item.html = escaped;
                                    item.outerHtml = opening[0] + escaped + closing[0];
                                    return this;
                                },
                                outerHtml() { return item.outerHtml || ''; },
                                equals(other) { return this === other; },
                                select(selector) {
                                    const rule = String(selector);
                                    const xpath = /^\s*(?:@xpath:|\/|\.\/|id\()/i.test(rule);
                                    const content = xpath && context
                                        ? {__readerXPathNode: context} : item.outerHtml || '';
                                    return _wrapElements(rule, content, xpath ? false : true);
                                },
                                toString() { return item.outerHtml || ''; }
                            };
                            if (htmlNodeId !== undefined) {
                                Object.defineProperty(wrapped, '__readerHtmlNodeId', {value: htmlNodeId});
                            }
                            return wrapped;
                        });
                        items.first = function() { return this.length ? this[0] : null; };
                        items.get = function(index) {
                            const position = Number(index);
                            return Number.isInteger(position) && position >= 0 && position < this.length
                                ? this[position] : null;
                        };
                        items.size = function() { return this.length; };
                        items.toArray = function() { return Array.from(this); };
                        return items;
                    };
                    const _wrapElements = (rule, content, rawCss = false, withNodeId = false) => {
                        content = _readerNodeContent(rule, content, rawCss);
                        const raw = _nativeGetElements(rule, content, rawCss, withNodeId);
                        let values;
                        try { values = JSON.parse(raw); } catch (e) { values = []; }
                        return _decorateItems(values, rawCss);
                    };
                    globalThis.__wrapReaderElements = values => _decorateItems(values, false);
                    if (Array.isArray(globalThis.result)) {
                        globalThis.result = _decorateItems(globalThis.result, false);
                    }
                    const _attachVariableMap = (value, scope) => {
                        if (!value || typeof value !== 'object') return;
                        if (typeof value.getVariable !== 'function') {
                            value.getVariable = function(key) {
                                const variables = this.variableMap || {};
                                const found = variables[String(key)];
                                return found == null ? '' : String(found);
                            };
                        }
                        if (typeof value.putVariable !== 'function') {
                            value.putVariable = function(key, val) {
                                const name = String(key);
                                if (!this.variableMap || typeof this.variableMap !== 'object') {
                                    this.variableMap = {};
                                }
                                const existed = Object.prototype.hasOwnProperty.call(this.variableMap, name);
                                const removed = val == null;
                                const text = removed ? '' : String(val);
                                if (removed) delete this.variableMap[name];
                                else this.variableMap[name] = text;
                                this.variable = JSON.stringify(this.variableMap);
                                java.__readerObjectVariablePut(scope, name, text, removed);
                                return existed;
                            };
                        }
                    };
                    _attachVariableMap(globalThis.book, 'book');
                    _attachVariableMap(globalThis.chapter, 'chapter');
                    const _attachGetters = (value, fields) => {
                        if (!value || typeof value !== 'object') return;
                        for (const field of fields) {
                            const name = 'get' + field[0].toUpperCase() + field.slice(1);
                            value[name] = function() { return this[field]; };
                        }
                    };
                    _attachGetters(globalThis.book, ['name', 'author', 'bookUrl', 'coverUrl', 'kind', 'wordCount']);
                    _attachGetters(globalThis.chapter, ['url', 'title', 'index']);
                    // Project extension: despite its name, this never refreshes or searches.
                    globalThis.java.refreshBookUrl = function() {
                        const url = globalThis.book && globalThis.book.bookUrl;
                        if (typeof url !== 'string' || url === '') {
                            throw new Error('refreshBookUrl requires current book.bookUrl');
                        }
                        return url;
                    };
                    if (globalThis.book && typeof globalThis.book === 'object') {
                        globalThis.book.getDisplayCover = function() {
                            return this.customCoverUrl == null || this.customCoverUrl === ''
                                ? this.coverUrl : this.customCoverUrl;
                        };
                        globalThis.book.getKindList = function() {
                            const values = new Packages.java.util.ArrayList();
                            // Kotlin Char.isWhitespace = Java whitespace or space-char;
                            // unlike JS trim, this keeps BOM and includes U+001C..U+001F.
                            const trimKind = text => text.replace(/^[\u0009-\u000d\u001c-\u0020\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u001c-\u0020\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g, '');
                            if (this.wordCount != null && trimKind(this.wordCount) !== '') {
                                values.add(this.wordCount);
                            }
                            if (this.kind != null) {
                                for (const item of this.kind.split(/[,\n]/)) {
                                    const text = trimKind(item);
                                    if (text !== '') values.add(text);
                                }
                            }
                            return values;
                        };
                    }
                    globalThis.java.getElements = _wrapElements;
                    globalThis.java.getElement = function(rule, content) {
                        const jsonValue = _nativeGetElement(rule, _readerNodeContent(rule, content, false));
                        if (jsonValue != null) return JSON.parse(jsonValue);
                        const items = _wrapElements(rule, content);
                        return items.length > 0 ? items[0] : null;
                    };
                }