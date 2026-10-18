(function() {
                    const java = globalThis.java;
                    const currentSource = globalThis.source;
                    // Source libraries may shadow the global Map helper.
                    const NativeMap = globalThis.Map;
                    const sourceAvailable = java.__sourceAvailable;
                    delete java.__sourceAvailable;
                    java.getSource = () => sourceAvailable ? currentSource : null;
                    java.startBrowser = function(url, title, html) {
                        if (!java.__browserPreview(String(url || ''), String(title || ''), String(html || ''))) {
                            throw new Error('网页只读预览失败或当前执行入口不支持预览');
                        }
                    };
                    java.startBrowserAwait = function(url, title) {
                        const response = JSON.parse(java.__browserAwait(
                            String(url || ''), String(title || '')));
                        if (!response.ok) {
                            const error = new Error(response.error.message);
                            error.kind = response.error.kind;
                            throw error;
                        }
                        const body = String(response.data.html || '');
                        return {body: () => body};
                    };
                    if (java.__clickCaptureActive) {
                        java.showReadingBrowser = java.startBrowser;
                        java.startBrowserDp = java.startBrowser;
                        java.showBrowser = function(url, html, preloadJs) {
                            if (preloadJs && String(preloadJs).trim() !== 'window.java=java;') {
                                throw new Error('不支持自定义网页预加载脚本');
                            }
                            java.startBrowser(url, '评论', html);
                        };
                    }
                    java.hostCall = function(operation, arguments) {
                        const response = JSON.parse(java.__hostCall(
                            String(operation), JSON.stringify(arguments == null ? null : arguments)));
                        if (!response.ok) {
                            const error = new Error(response.error.message);
                            error.kind = response.error.kind;
                            throw error;
                        }
                        return response.data;
                    };
                    const chineseConvert = (direction, value) => {
                        const text = String(value == null ? '' : value);
                        if (text.length > 65536) {
                            const error = new Error('Chinese text input too large');
                            error.kind = 'limit_exceeded'; throw error;
                        }
                        if (text === '') return '';
                        const output = java.hostCall('text.chinese.convert', {direction, text});
                        if (typeof output !== 'string' || output.length > 262144) {
                            const error = new Error('invalid Chinese conversion response');
                            error.kind = 'invalid_response'; throw error;
                        }
                        return output;
                    };
                    java.t2s = value => chineseConvert('t2s', value);
                    java.s2t = value => chineseConvert('s2t', value);
                    const nativeSourceSetVariable = globalThis.source.setVariable;
                    const nativeSourceRemoveVariable = globalThis.source.__removeVariable;
                    const nativeSourceRemoveLoginInfo = globalThis.source.__removeLoginInfo;
                    const nativeSourceGetLoginHeader = globalThis.source.getLoginHeader;
                    globalThis.source.removeLoginInfo = function() {
                        nativeSourceRemoveLoginInfo();
                        globalThis.loginInfo = null;
                    };
                    globalThis.source.getLoginHeader = function() {
                        const value = nativeSourceGetLoginHeader();
                        return value == null ? null : value;
                    };
                    globalThis.source.getLoginHeaderMap = function() {
                        const raw = source.getLoginHeader();
                        if (raw == null) return null;
                        let value;
                        try { value = JSON.parse(raw); } catch (_) { return null; }
                        return value && typeof value === 'object' && !Array.isArray(value)
                            ? new NativeMap(Object.entries(value).map(([key, item]) => [key, String(item)]))
                            : null;
                    };
                    globalThis.source.setVariable = function(value, extendedValue) {
                        if (arguments.length > 1) {
                            nativeSourceSetVariable(
                                String(value == null ? '' : value),
                                String(extendedValue == null ? '' : extendedValue));
                            return;
                        }
                        if (value == null) {
                            nativeSourceRemoveVariable();
                            return;
                        }
                        nativeSourceSetVariable(String(value));
                    };
                    const nativeBase64Encode = java.base64Encode;
                    const nativeBase64Decode = java.base64Decode;
                    const cryptoResult = (name, algorithm, value) => {
                        if (value == null) {
                            throw new Error(name + ': unsupported algorithm ' + algorithm);
                        }
                        return value;
                    };
                    java.digestHex = (data, algorithm) => cryptoResult(
                        'digestHex', algorithm,
                        java.__digestHex(String(data), String(algorithm)));
                    java.digestBase64Str = (data, algorithm) => cryptoResult(
                        'digestBase64Str', algorithm,
                        java.__digestBase64(String(data), String(algorithm)));
                    // Legacy MD5 is provided by KOReader's ffi/sha2; SHA stays native.
                    const isHmacMd5 = algorithm => String(algorithm)
                        .replace(/[^a-z0-9]/gi, '').toUpperCase() === 'HMACMD5';
                    const hostHmacMd5 = java.__hostHmacMd5 = (keyHex, dataHex) => {
                        if (keyHex.length > 32768 || dataHex.length > 524288) {
                            const error = new Error('HMAC input too large');
                            error.kind = 'limit_exceeded'; throw error;
                        }
                        const output = java.hostCall('crypto.hmac', {
                            algorithm: 'HMACMD5', keyHex, dataHex
                        });
                        if (typeof output !== 'string' || !/^[0-9a-f]{32}$/i.test(output)) {
                            const error = new Error('invalid HMAC response');
                            error.kind = 'invalid_response'; throw error;
                        }
                        return output.toLowerCase();
                    };
                    java.HMacHex = (data, algorithm, key) => isHmacMd5(algorithm)
                        ? hostHmacMd5(java.hexEncodeToString(String(key)), java.hexEncodeToString(String(data)))
                        : cryptoResult('HMacHex', algorithm,
                            java.__hmacHexString(String(data), String(algorithm), String(key)));
                    java.HMacBase64 = (data, algorithm, key) => isHmacMd5(algorithm)
                        ? java.__base64EncodeBytes(JSON.stringify(java.hexDecodeToByteArray(
                            java.HMacHex(data, algorithm, key))), 2)
                        : cryptoResult('HMacBase64', algorithm,
                            java.__hmacBase64String(String(data), String(algorithm), String(key)));
                    java.toURL = function(url, baseUrl) {
                        const payload = baseUrl == null
                            ? java.__toURL(String(url))
                            : java.__toURL(String(url), String(baseUrl));
                        const raw = JSON.parse(payload);
                        if (raw.error) throw new Error(raw.error);
                        return {
                            searchParams: raw.searchParams == null
                                ? null
                                : new NativeMap(Object.entries(raw.searchParams)),
                            host: String(raw.host || ''),
                            origin: String(raw.origin || ''),
                            pathname: String(raw.pathname || '')
                        };
                    };
                    java.logType = value => {
                        let type;
                        if (value === null || value === undefined) type = 'null';
                        else if (typeof value === 'string') type = 'java.lang.String';
                        else if (typeof value === 'boolean') type = 'java.lang.Boolean';
                        else if (typeof value === 'number') type = 'java.lang.Double';
                        else if (value instanceof Uint8Array) type = '[B';
                        else if (Array.isArray(value)) type = 'org.mozilla.javascript.NativeArray';
                        else if (typeof value === 'function') type = 'org.mozilla.javascript.NativeFunction';
                        else type = 'org.mozilla.javascript.NativeObject';
                        java.log(type);
                    };
                    const headersJson = headers => {
                        if (headers == null) return '{}';
                        if (typeof headers === 'string') {
                            try {
                                const parsed = JSON.parse(headers);
                                return JSON.stringify(parsed && typeof parsed === 'object' ? parsed : {});
                            } catch (_) { return '{}'; }
                        }
                        return typeof headers === 'object' ? JSON.stringify(headers) : '{}';
                    };
                    const responseFromJson = value => {
                        let raw;
                        try { raw = JSON.parse(String(value || '{}')); } catch (_) { raw = {}; }
                        let body = String(raw.body == null ? '' : raw.body);
                        let charset = raw.charset == null ? null : String(raw.charset);
                        const headers = Object.assign({}, raw.headers || {});
                        const status = Number(raw.code || raw.status || 0);
                        const headerValues = raw.headerValues || {};
                        const responseCookies = new NativeMap();
                        for (const [name, values] of Object.entries(headerValues)) {
                            if (name.toLowerCase() !== 'set-cookie') continue;
                            for (const value of values) {
                                const pair = String(value).split(';', 1)[0];
                                const equals = pair.indexOf('=');
                                if (equals <= 0) continue;
                                responseCookies.set(pair.slice(0, equals).trim(), pair.slice(equals + 1).trim());
                            }
                        }
                        const header = name => {
                            const key = Object.keys(headers).find(k => k.toLowerCase() === String(name).toLowerCase());
                            return key === undefined ? null : headers[key];
                        };
                        const responseHeaders = Object.assign({}, headers, {
                            get: name => header(name),
                            names: () => Object.keys(headers),
                            toMultimap: () => Object.assign({}, headers)
                        });
                        return {
                            body: () => body,
                            bodyAsBytes: () => java.base64DecodeToByteArray(raw.bodyBase64 || ''),
                            statusCode: () => status,
                            code: () => status,
                            url: () => String(raw.url || ''),
                            headers: () => responseHeaders,
                            header,
                            hasHeader: name => header(name) !== null,
                            multiHeaders: () => new NativeMap(Object.entries(headerValues)),
                            cookies: () => responseCookies,
                            cookie: name => responseCookies.has(String(name)) ? responseCookies.get(String(name)) : null,
                            hasCookie: name => responseCookies.has(String(name)),
                            contentType: () => header('content-type') || '',
                            charset: () => charset,
                            parse() {
                                const decoded = java.__responseDecodeText(String(raw.bodyBase64 || ''), charset, true);
                                if (decoded == null) throw new Error('invalid response bytes');
                                const parsed = JSON.parse(decoded);
                                const document = org.jsoup.Jsoup.parse(parsed.text, String(raw.url || ''));
                                charset = parsed.charset;
                                // body() decodes the original bytes; parse() alone consumes a BOM.
                                body = JSON.parse(java.__responseDecodeText(String(raw.bodyBase64 || ''), charset, false)).text;
                                return document;
                            },
                            isSuccessful: () => status >= 200 && status < 300,
                            toString: () => body,
                            toJSON: () => raw
                        };
                    };
                    const nativeVariableGet = java.__nativeVariableGet;
                    java.ajax = value => {
                        const target = Array.isArray(value) ? value[0] : value;
                        return java.__nativeAjax(String(target == null ? '' : target));
                    };
                    java.importScript = path => {
                        const value = java.__importScript(String(path == null ? '' : path));
                        if (value == null) {
                            throw new Error('importScript: content is empty or local paths are unsupported by this host');
                        }
                        return value;
                    };
                    java.webView = (html, url, js) => java.__nativeWebView(
                        String(html == null ? '' : html),
                        String(url == null ? '' : url),
                        String(js == null ? '' : js)
                    );
                    java.get = function(url, headers) {
                        const target = String(url == null ? '' : url);
                        if (arguments.length < 2 && !/^https?:\/\//i.test(target)) {
                            return nativeVariableGet(target);
                        }
                        return responseFromJson(java.__nativeGet(target, headersJson(headers)));
                    };
                    java.post = (url, body, headers) => responseFromJson(java.__nativePost(
                        String(url), String(body == null ? '' : body), headersJson(headers)));
                    java.head = (url, headers) => responseFromJson(java.__nativeHead(
                        String(url), headersJson(headers)));
                    const callableString = text => new Proxy(() => text, {
                        get(target, key) {
                            if (key === Symbol.toPrimitive || key === 'toJSON') return () => text;
                            if (key in String.prototype || key === 'length' || /^\d+$/.test(String(key))) {
                                const value = text[key];
                                return typeof value === 'function' ? value.bind(text) : value;
                            }
                            return Reflect.get(target, key);
                        }
                    });
                    const strResponseFromJson = value => {
                        let raw;
                        try { raw = typeof value === 'string' ? JSON.parse(value) : value || {}; }
                        catch (_) { raw = {}; }
                        const bodyText = String(raw.body == null ? '' : raw.body);
                        const url = String(raw.url || '');
                        const code = Number(raw.code ?? raw.status ?? 200);
                        const message = String(raw.message == null ? 'OK' : raw.message);
                        const headers = Object.assign({}, raw.headers || {});
                        const responseHeaders = Object.assign({}, headers, {
                            get(name) {
                                const key = Object.keys(headers).find(k => k.toLowerCase() === String(name).toLowerCase());
                                return key === undefined ? null : headers[key];
                            },
                            names: () => Object.keys(headers),
                            toMultimap: () => Object.assign({}, headers)
                        });
                        const isSuccessful = raw.isSuccessful == null
                            ? code >= 200 && code < 300 : !!raw.isSuccessful;
                        const rawResponseBody = () => {
                            const value = new String(bodyText);
                            value.string = () => bodyText;
                            value.close = () => {};
                            return value;
                        };
                        const rawRequest = { url: () => url };
                        const rawResponse = {
                            request: () => rawRequest,
                            body: rawResponseBody,
                            url: () => url,
                            code: () => code,
                            message: () => message,
                            headers: () => responseHeaders,
                            isSuccessful: () => isSuccessful,
                            toString: () => `Response{code=${code}, message=${message}, url=${url}}`
                        };
                        return {
                            __ffiStrResponse: true,
                            body: callableString(bodyText),
                            header: name => responseHeaders.get(name),
                            url: () => url,
                            code: () => code,
                            message: () => message,
                            headers: () => responseHeaders,
                            raw: () => rawResponse,
                            isSuccessful: () => isSuccessful,
                            toString: () => rawResponse.toString(),
                            toJSON: () => ({
                                __ffiStrResponse: true,
                                body: bodyText,
                                url,
                                code,
                                message,
                                headers,
                                isSuccessful
                            })
                        };
                    };
                    globalThis.__readerMakeStrResponse = strResponseFromJson;
                    java.connect = (url, headers) => strResponseFromJson(
                        java.__nativeConnect(
                            String(url), headers == null ? '' : headersJson(headers)));
                    java.ajaxAll = urls => Array.from(urls || [], url =>
                        strResponseFromJson(java.__nativeAjaxAllItem(String(url))));
                    java.strToBytes = (value, charset) => JSON.parse(
                        java.__strToBytes(String(value), charset == null ? '' : String(charset)));
                    java.bytesToStr = (bytes, charset) => java.__bytesToStr(
                        JSON.stringify(Array.from(bytes == null ? [] : bytes)),
                        charset == null ? '' : String(charset));
                    java.hexDecodeToByteArray = value => JSON.parse(
                        java.__hexDecodeBytes(String(value)));
                    java.base64Encode = function(value, flags) {
                        const text = String(value == null ? '' : value);
                        if (arguments.length < 2) return nativeBase64Encode(text);
                        return java.__base64EncodeBytes(
                            JSON.stringify(java.strToBytes(text, 'UTF-8')),
                            Number(flags || 0));
                    };
                    java.base64Decode = function(value, charsetOrFlags) {
                        const text = String(value == null ? '' : value);
                        if (typeof charsetOrFlags === 'number') {
                            const bytes = JSON.parse(java.__base64DecodeBytes(
                                text, Number(charsetOrFlags)));
                            return java.bytesToStr(bytes, 'UTF-8');
                        }
                        return charsetOrFlags == null
                            ? nativeBase64Decode(text)
                            : nativeBase64Decode(text, String(charsetOrFlags));
                    };
                    java.base64DecodeToByteArray = function(value, flags) {
                        if (value == null || String(value).trim() === '') return null;
                        return JSON.parse(java.__base64DecodeBytes(
                            String(value), Number(flags || 0)));
                    };
                    const fileCacheCall = (action, arguments) => {
                        const response = JSON.parse(java.__fileCache(action, JSON.stringify(arguments)));
                        if (!response.ok) {
                            const error = new Error(response.error.message);
                            error.kind = response.error.kind; throw error;
                        }
                        return response.data;
                    };
                    globalThis.cache.getFile = key => {
                        const value = fileCacheCall('get', {key: String(key)});
                        if (value !== null && (typeof value !== 'string' || value.length > 262144)) {
                            const error = new Error('invalid file cache response');
                            error.kind = 'invalid_response'; throw error;
                        }
                        return value;
                    };
                    globalThis.cache.putFile = (key, value, saveTime) => {
                        const ttl = saveTime == null ? 0 : Number(saveTime);
                        const text = String(value == null ? '' : value);
                        if (!Number.isInteger(ttl) || ttl < -2147483648 || ttl > 2147483647
                            || text.length > 262144) {
                            const error = new Error('invalid file cache value or TTL');
                            error.kind = 'invalid_argument'; throw error;
                        }
                        if (fileCacheCall('put', {key: String(key), value: text, saveTime: ttl}) !== true) {
                            const error = new Error('invalid file cache write response');
                            error.kind = 'invalid_response'; throw error;
                        }
                    };
                    const nativeCacheGet = globalThis.cache.get;
                    const nativeCachePut = globalThis.cache.put;
                    const nativeCacheDelete = globalThis.cache.delete;
                    globalThis.cache.get = key => {
                        const value = nativeCacheGet(String(key));
                        return value == null ? null : value;
                    };
                    globalThis.cache.put = (key, value, saveTime) => {
                        let stored;
                        if (typeof value === 'string') stored = value;
                        else {
                            try { stored = JSON.stringify(value); }
                            catch (_) { stored = String(value); }
                        }
                        if (stored === undefined) stored = String(value);
                        const ok = saveTime == null
                            ? nativeCachePut(String(key), stored)
                            : nativeCachePut(String(key), stored, Number(saveTime));
                        if (!ok) throw new Error('cache.put: session cache limit exceeded');
                    };
                    globalThis.cache.delete = key => {
                        key = String(key);
                        try {
                            if (fileCacheCall('delete', {key}) !== true) {
                                const error = new Error('invalid file cache delete response');
                                error.kind = 'invalid_response'; throw error;
                            }
                        } catch (error) {
                            // Keep legacy memory-only deletion when the optional
                            // service/source context is not configured. Real errors
                            // are terminal and must not clear memory or be retried.
                            if (error.kind !== 'unavailable' && error.kind !== 'unsupported') throw error;
                        }
                        nativeCacheDelete(key);
                        localMemory.delete(key);
                        cache.__memoryDelete(key);
                    };
                    // Memory entries are per active FFI operation, never persisted
                    // into the caller's session delta or shared across users.
                    const localMemory = new Map();
                    globalThis.cache.getFromMemory = key => {
                        key = String(key);
                        const stored = cache.__memoryGet(key);
                        return stored == null ? (localMemory.get(key) ?? null) : JSON.parse(stored);
                    };
                    globalThis.cache.putMemory = (key, value) => {
                        key = String(key);
                        localMemory.set(key, value);
                        const encoded = JSON.stringify(value);
                        if (encoded !== undefined) cache.__memoryPut(key, encoded);
                    };
                    globalThis.cache.deleteMemory = key => {
                        key = String(key);
                        localMemory.delete(key);
                        cache.__memoryDelete(key);
                    };
                })();