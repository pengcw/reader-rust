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
                    let currentHtmlContent = null;
                    const _orig_getString = globalThis.java.getString;
                    globalThis.java.getString = function(rule, content, isUrl, unescape) {
                        const r = (rule !== undefined && rule !== null) ? String(rule) : undefined;
                        if (content === undefined && currentHtmlContent) {
                            if (r === 'text') return currentHtmlContent.text();
                            if (r === 'href') return currentHtmlContent.attr('href');
                        }
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
                    const appendListValue = function(value) {
                        if (arguments.length !== 1) throw new TypeError('unsupported list.add overload');
                        this.push(value);
                        return true;
                    };
                    const listIndex = (index, length) => {
                        if (!Number.isInteger(index) || index < 0 || index >= length)
                            throw new RangeError('list index out of bounds');
                        return index;
                    };
                    const listSize = function() {
                        if (arguments.length !== 0) throw new TypeError('list.size takes no arguments');
                        return this.length;
                    };
                    const listGet = function(index) {
                        if (arguments.length !== 1) throw new TypeError('list.get requires one index');
                        return this[listIndex(index, this.length)];
                    };
                    const listSet = function(index, value) {
                        if (arguments.length !== 2) throw new TypeError('list.set requires index and value');
                        const position = listIndex(index, this.length);
                        const previous = this[position];
                        this[position] = value;
                        return previous;
                    };
                    // Jsoup TextNode lists retain direct-child boundaries and Java List string form.
                    java.__jsoupTextNodeList = elements => {
                        const nodes = [];
                        for (const element of elements) {
                            const rawNodes = JSON.parse(java.__jsoupTextNodes(String(element.outerHtml())));
                            for (const raw of rawNodes) {
                                nodes.push({
                                    nodeName: () => '#text',
                                    getWholeText: () => raw,
                                    text: () => raw.replace(/[\u200B\u00AD]/g, '')
                                        .replace(/[ \t\n\r\f\u00A0]+/g, ' '),
                                    toString: () => raw.replace(/&/g, '&amp;')
                                        .replace(/</g, '&lt;').replace(/>/g, '&gt;')
                                });
                            }
                        }
                        Object.defineProperties(nodes, {
                            size: { value: () => nodes.length },
                            get: { value: index => nodes[listIndex(Number(index), nodes.length)] },
                            isEmpty: { value: () => nodes.length === 0 },
                            toArray: { value: () => Array.from(nodes) },
                            toString: { value: () => '[' + nodes.map(String).join(', ') + ']' }
                        });
                        return nodes;
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
                            size: { value: listSize },
                            add: { value: appendListValue },
                            get: { value: listGet },
                            set: { value: listSet },
                            toArray: { value: function() { return Array.from(this); } }
                        });
                        return values;
                    };
                    const _nativeSetContent = globalThis.java.__setContent;
                    globalThis.java.setContent = function(content, newBaseUrl) {
                        if (content == null) throw new Error('content cannot be null');
                        const htmlNode = typeof content.outerHtml === 'function'
                            && typeof content.select === 'function' && !content.__readerXPathNode;
                        currentHtmlContent = htmlNode ? content : null;
                        if (htmlNode) {
                            content = content.outerHtml();
                        } else if (typeof content === 'object') {
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
                    const _decorateItems = (values, rawCss = false, existingNodes = false) => {
                        if (!Array.isArray(values)) values = [];
                        const carrier = existingNodes ? null : values.find(item => item && item.__readerXPathNode
                            && typeof item.__readerXPathNode.document === 'string');
                        const documentId = carrier ? _internXPathDocument(carrier.__readerXPathNode.document) : undefined;
                        // Derived Jsoup collections already contain wrapped elements. Copy the
                        // list, not the nodes, while keeping the existing list methods.
                        const items = existingNodes ? values.slice() : values.map(item => {
                            if (!item || item.__readerHtmlElement !== true) return item;
                            const attrs = item.attrs || {};
                            const htmlNodeId = item.__readerHtmlNodeId;
                            const ancestorIds = item.__readerHtmlAncestors;
                            delete item.__readerHtmlNodeId;
                            delete item.__readerHtmlAncestors;
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
                                ownText() {
                                    const tag = this.tagName();
                                    return tag ? java.getString(tag + '@ownText', item.outerHtml || '') : '';
                                },
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
                                textNodes() { return java.__jsoupTextNodeList([this]); },
                                equals(other) { return this === other; },
                                is(selector) {
                                    const markup = String(this.outerHtml());
                                    return _wrapElements(String(selector), markup, true).some(node =>
                                        String(node.outerHtml()) === markup);
                                },
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
                            if (ancestorIds !== undefined) {
                                Object.defineProperty(wrapped, '__readerHtmlAncestors', {value: ancestorIds});
                            }
                            return wrapped;
                        });
                        // List methods are not enumerable: source JS often uses for-in.
                        Object.defineProperties(items, {
                            first: { value: function() { return this.length ? this[0] : null; } },
                            last: { value: function() { return this.length ? this[this.length - 1] : null; } },
                            get: { value: listGet },
                            set: { value: listSet },
                            add: { value: appendListValue },
                            size: { value: listSize },
                            isEmpty: { value: function() { return this.length === 0; } },
                            toArray: { value: function() { return Array.from(this); } },
                            eq: { value: function(index) {
                                if (Number.isInteger(index) && index < 0) throw new RangeError('list index out of bounds');
                                return _decorateItems(Number.isInteger(index) && index < this.length
                                    ? [this[index]] : [], rawCss);
                            }, writable: true, configurable: true },
                            text: { value: function() { return this.map(item => item.text()).join(' '); }, writable: true, configurable: true },
                            textNodes: { value: function() { return java.__jsoupTextNodeList(this); } },
                            attr: { value: function(name) {
                                const item = this.find(item => item.hasAttr(name));
                                return item ? item.attr(name) : '';
                            }, writable: true, configurable: true },
                            html: { value: function() { return this.map(item => item.html()).join('\n'); }, writable: true, configurable: true }
                        });
                        if (items.every(item => item && typeof item.select === 'function'
                                && typeof item.outerHtml === 'function')) {
                            Object.defineProperties(items, {
                                hasAttr: { value: function(name) { return this.some(item => item.hasAttr(name)); } },
                                is: { value: function(selector) { return this.not(selector).length !== this.length; } },
                                select: { writable: true, configurable: true, value: function(selector) {
                                    const selected = [];
                                    for (const item of this) {
                                        for (const match of item.select(selector)) selected.push(match);
                                    }
                                    return _decorateItems(selected, true);
                                } },
                                not: { writable: true, configurable: true, value: function(selector) {
                                    return _decorateItems(this.filter(item => {
                                        const matches = _wrapElements(selector, item.outerHtml(), true);
                                        return !matches.some(match =>
                                            String(match.outerHtml()) === String(item.outerHtml()));
                                    }), rawCss);
                                } }
                            });
                        }
                        return items;
                    };
                    const _wrapElements = (rule, content, rawCss = false, withNodeId = false) => {
                        content = _readerNodeContent(rule, content, rawCss);
                        const raw = _nativeGetElements(rule, content, rawCss, withNodeId);
                        let values;
                        try { values = JSON.parse(raw); } catch (e) { values = []; }
                        return _decorateItems(values, rawCss);
                    };
                    globalThis.__wrapReaderElements = (values, existingNodes = false) =>
                        _decorateItems(values, false, existingNodes);
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