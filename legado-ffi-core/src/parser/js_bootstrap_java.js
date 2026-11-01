(function() {
                    const java = globalThis.java;
                    const currentSource = globalThis.source;
                    // Source libraries may shadow the global Map helper.
                    const NativeMap = globalThis.Map;
                    const sourceAvailable = java.__sourceAvailable;
                    delete java.__sourceAvailable;
                    java.getSource = () => sourceAvailable ? currentSource : null;
                    java.getTag = () => java.getSource()?.bookSourceName ?? null;
                    java.hasJavaClass = name => {
                        if (typeof name !== 'string') return false;
                        let obj = Packages;
                        for (const part of name.split('.')) {
                            if (!obj || !Object.prototype.hasOwnProperty.call(obj, part)) {
                                return false;
                            }
                            obj = obj[part];
                        }
                        return !!obj && Object.prototype.hasOwnProperty.call(obj, '__javaCompatClass')
                            && obj.__javaCompatClass === true;
                    };
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
                    java.reLoginView = function(deltaUp = false) {
                        if (typeof deltaUp !== 'boolean') throw new TypeError('reLoginView expects a boolean');
                        if (!java.__reLoginView(deltaUp)) {
                            throw new Error('reLoginView requires a login or discovery action');
                        }
                    };
                    // Finite read-only compatibility defaults, not Android device settings.
                    const readConfigDefaults = Object.freeze({
                        name: 'KOReader', bgStr: '#FFFFFF', bgStrNight: '#FFFFFF', bgStrEInk: '#FFFFFF',
                        bgAlpha: 100, bgType: 0, bgTypeNight: 0, bgTypeEInk: 0,
                        textColor: '#000000', textColorNight: '#000000', textColorEInk: '#000000',
                        textAccentColor: '#000000', textAccentColorNight: '#000000', textAccentColorEInk: '#000000',
                        textFont: '', textBold: 0, textSize: 20, letterSpacing: 0,
                        lineSpacingExtra: 0, paragraphSpacing: 0, paragraphIndent: '　　',
                        pageAnim: 0, pageAnimEInk: 0, titleMode: 0,
                        paddingTop: 0, paddingBottom: 0, paddingLeft: 0, paddingRight: 0
                    });
                    const configNightMode = () => {
                        try {
                            const snapshot = java.hostCall('reader.config.snapshot', null);
                            if (!snapshot || typeof snapshot.isNightTheme !== 'boolean') {
                                throw new TypeError('Invalid reader configuration snapshot');
                            }
                            return snapshot.isNightTheme;
                        } catch (error) {
                            if (error.kind === 'unsupported' || error.kind === 'unavailable') return false;
                            throw error;
                        }
                    };
                    java.getReadBookConfigMap = () => ({...readConfigDefaults});
                    java.getReadBookConfig = () => JSON.stringify(java.getReadBookConfigMap());
                    java.getThemeConfigMap = () => ({isNightTheme: configNightMode()});
                    java.getThemeConfig = () => JSON.stringify(java.getThemeConfigMap());
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
                        try { value = JSON.parse(raw); } catch { return null; }
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
                    globalThis.source.putVariable = function(value) {
                        globalThis.source.setVariable(value);
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
                            } catch { return '{}'; }
                        }
                        return typeof headers === 'object' ? JSON.stringify(headers) : '{}';
                    };
                    const responseFromJson = value => {
                        let raw;
                        try { raw = JSON.parse(String(value || '{}')); } catch { raw = {}; }
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
                    const requestCallTimeout = value => {
                        if (value == null) return undefined;
                        if (!Number.isInteger(value) || value < 1 || value > 120000) {
                            throw new TypeError('callTimeout must be an integer from 1 to 120000 milliseconds');
                        }
                        return value;
                    };
                    java.ajax = (value, callTimeout) => {
                        const target = Array.isArray(value) ? value[0] : value;
                        return java.__nativeAjax(String(target == null ? '' : target), requestCallTimeout(callTimeout));
                    };
                    // UI belongs to the host; native only collects interactive login actions.
                    java.openUrl = (url, mimeType) => java.__openUrl(
                        String(url == null ? '' : url),
                        mimeType == null ? null : String(mimeType));
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
                    java.get = function(url, headers, timeout) {
                        const target = String(url == null ? '' : url);
                        if (arguments.length < 2 && !/^https?:\/\//i.test(target)) {
                            return nativeVariableGet(target);
                        }
                        return responseFromJson(java.__nativeGet(target, headersJson(headers), requestCallTimeout(timeout)));
                    };
                    java.post = (url, body, headers, timeout) => responseFromJson(java.__nativePost(
                        String(url), String(body == null ? '' : body), headersJson(headers), requestCallTimeout(timeout)));
                    java.head = (url, headers, timeout) => responseFromJson(java.__nativeHead(
                        String(url), headersJson(headers), requestCallTimeout(timeout)));
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
                        catch { raw = {}; }
                        const bodyText = String(raw.body == null ? '' : raw.body);
                        const url = String(raw.url || '');
                        const code = Number(raw.code ?? raw.status ?? 200);
                        const callTime = Number(raw.callTime ?? 0);
                        const errorBody = raw.errorBody ?? null;
                        const message = String(raw.message == null ? 'OK' : raw.message);
                        const headers = Object.assign({}, raw.headers || {});
                        const headerValues = raw.headerValues || {};
                        const responseHeaders = Object.assign({}, headers, {
                            get(name) {
                                const key = Object.keys(headers).find(k => k.toLowerCase() === String(name).toLowerCase());
                                return key === undefined ? null : headers[key];
                            },
                            values(name) {
                                const key = Object.keys(headerValues).find(k => k.toLowerCase() === String(name).toLowerCase());
                                if (key !== undefined) return [...headerValues[key]];
                                const value = this.get(name);
                                return value == null ? [] : [value];
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
                            callTime: () => callTime,
                            errorBody: () => errorBody,
                            isSuccessful: () => isSuccessful,
                            toString: () => rawResponse.toString(),
                            toJSON: () => ({
                                __ffiStrResponse: true,
                                body: bodyText,
                                url,
                                code,
                                message,
                                headers,
                                headerValues,
                                isSuccessful,
                                callTime,
                                errorBody
                            })
                        };
                    };
                    globalThis.__readerMakeStrResponse = strResponseFromJson;
                    if (java.__loginGetStrResponse) {
                        // A single facade reads the active RequestSpec on every operation.
                        // Never mutate source defaults or return an unlinked Map snapshot.
                        const currentHeaders = () => JSON.parse(java.__loginHeaderMap());
                        const findHeader = name => currentHeaders().find(
                            ([key]) => key === String(name));
                        const headerMap = {
                            get(name) {
                                const pair = findHeader(name);
                                return pair ? pair[1] : null;
                            },
                            containsKey(name) { return !!findHeader(name); },
                            put(name, value) {
                                const old = this.get(name);
                                java.__loginPutHeaders(JSON.stringify([[String(name), String(value)]]));
                                return old;
                            },
                            putAll(values) {
                                const pairs = values instanceof NativeMap ? [...values.entries()]
                                    : values && typeof values === 'object' && !Array.isArray(values)
                                        ? Object.entries(values) : null;
                                if (!pairs) throw new TypeError('putAll expects a map');
                                java.__loginPutHeaders(JSON.stringify(pairs.map(([name, value]) =>
                                    [String(name), String(value)])));
                            },
                            size() { return currentHeaders().length; },
                            isEmpty() { return currentHeaders().length === 0; }
                        };
                        java.getHeaderMap = function() {
                            if (arguments.length) throw new TypeError('getHeaderMap takes no arguments');
                            return headerMap;
                        };
                        java.headerMap = headerMap;
                        let initializingLoginUrl = false;
                        java.initUrl = function() {
                            if (arguments.length) throw new TypeError('initUrl takes no arguments');
                            if (initializingLoginUrl) throw new Error('recursive initUrl is not supported');
                            initializingLoginUrl = true;
                            try {
                                const updated = JSON.parse(java.__loginInitUrl());
                                java.url = updated.url;
                                java.ruleUrl = updated.ruleUrl;
                            } finally {
                                initializingLoginUrl = false;
                            }
                        };
                        java.getResponse = function() {
                            if (arguments.length) throw new TypeError('getResponse takes no arguments');
                            const headers = JSON.parse(java.__loginGetResponseHeaders());
                            const facade = { get(name) {
                                const key = String(name).toLowerCase();
                                for (let i = headers.length - 1; i >= 0; i--) {
                                    if (headers[i][0].toLowerCase() === key) return headers[i][1];
                                }
                                return null;
                            }};
                            return { headers: () => facade };
                        };
                        let retryingLoginRequest = false;
                        java.getStrResponse = function(jsStr, sourceRegex, useWebView) {
                            const directHttp = arguments.length === 3
                                && jsStr == null && sourceRegex == null && useWebView === false;
                            const defaultHttp = arguments.length === 2 && jsStr == null && sourceRegex == null;
                            if (arguments.length !== 0 && !defaultHttp && !directHttp) {
                                throw new TypeError('getStrResponse arguments are not supported by this host');
                            }
                            if (retryingLoginRequest) {
                                throw new Error('recursive getStrResponse is not supported');
                            }
                            retryingLoginRequest = true;
                            try {
                                return strResponseFromJson(java.__loginGetStrResponse(!directHttp));
                            } finally {
                                retryingLoginRequest = false;
                            }
                        };
                    }
                    java.connect = (url, headers, callTimeout) => strResponseFromJson(
                        java.__nativeConnect(
                            String(url), headers == null ? '' : headersJson(headers), requestCallTimeout(callTimeout)));
                    java.ajaxAll = urls => Array.from(urls || [], url =>
                        strResponseFromJson(java.__nativeAjaxAllItem(String(url))));
                    java.ajaxTestAll = (urls, timeout, _skipRateLimit) => {
                        // Rate limiting belongs to the host; keep this batch serial like ajaxAll.
                        const ms = requestCallTimeout(timeout);
                        if (ms === undefined) throw new TypeError('ajaxTestAll requires a timeout');
                        return Array.from(urls || [], url =>
                            strResponseFromJson(java.__nativeAjaxTestAllItem(String(url), ms)));
                    };
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
                    java.cacheFile = (url, saveTime = 0) => {
                        if (typeof url !== 'string' || !url.trim()
                            || !Number.isInteger(saveTime) || saveTime < 0 || saveTime > 2147483647) {
                            throw new TypeError('cacheFile requires a URL and non-negative integer TTL in seconds');
                        }
                        const key = 'cacheFile:' + java.md5Encode(url);
                        const cached = globalThis.cache.getFile(key);
                        if (cached !== null && cached.trim() !== '') return cached;
                        const text = java.__cacheFileText(url);
                        if (text.trim() !== '') globalThis.cache.putFile(key, text, saveTime);
                        return text;
                    };
                    // Limited QueryTTF objects are private maps, never persistent native handles.
                    const fontObjects = new WeakMap();
                    const fontCache = new NativeMap();
                    const fontBlanks = new Set([9,32,160,8194,8195,8199,8202,8203,8204,8205,8239,8287]);
                    const fontFailure = (kind, message) => {
                        const error = new Error(message); error.kind = kind; throw error;
                    };
                    java.queryTTF = function(data, useCache = true) {
                        if (data == null) return null;
                        if (typeof useCache !== 'boolean') throw new TypeError('queryTTF cache flag must be boolean');
                        let input;
                        if (typeof data === 'string') {
                            if (data.length > 1048576) fontFailure('limit_exceeded', 'font input too large');
                            input = data;
                        } else if (Array.isArray(data) || data instanceof Uint8Array) {
                            if (data.length > 524288) fontFailure('limit_exceeded', 'font byte input too large');
                            input = Array.from(data, byte => {
                                if (!Number.isInteger(byte) || byte < -128 || byte > 255) {
                                    throw new TypeError('invalid font byte');
                                }
                                return (byte + 256) % 256;
                            });
                        } else return null;
                        const key = useCache ? java.digestHex(JSON.stringify(input), 'SHA-256') : null;
                        if (useCache && fontCache.has(key)) return fontCache.get(key);
                        let bytes;
                        if (typeof input !== 'string') bytes = input;
                        else if (/^https?:\/\//i.test(input)) {
                            let response;
                            try { response = JSON.parse(java.__fontInput(input)); }
                            catch { fontFailure('invalid_response', 'invalid font download response'); }
                            if (!response.ok) fontFailure(response.error.kind, response.error.message);
                            bytes = response.data;
                        } else bytes = java.base64DecodeToByteArray(input);
                        if (!Array.isArray(bytes) || bytes.length > 524288
                            || !bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
                            fontFailure('invalid_response', 'invalid downloaded font bytes');
                        }
                        const parsed = java.hostCall('font.parse', {data: bytes});
                        if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.entries)
                            || parsed.entries.length > 8192) fontFailure('invalid_response', 'invalid font metadata');
                        const characters = new NativeMap();
                        for (const entry of parsed.entries) {
                            if (!Array.isArray(entry) || entry.length !== 3
                                || !Number.isInteger(entry[0]) || entry[0] < 0 || entry[0] > 65535
                                || !Number.isInteger(entry[1]) || entry[1] < 1 || entry[1] >= 8192
                                || characters.has(entry[0])
                                || (entry[2] !== false && (typeof entry[2] !== 'string' || !/^[0-9a-f]{64}$/.test(entry[2])))) {
                                fontFailure('invalid_response', 'invalid font mapping');
                            }
                            characters.set(entry[0], entry[2]);
                        }
                        const object = Object.freeze({});
                        fontObjects.set(object, {characters, inverse: null});
                        if (useCache) {
                            if (fontCache.size >= 4) fontCache.delete(fontCache.keys().next().value);
                            fontCache.set(key, object);
                        }
                        return object;
                    };
                    java.queryBase64TTF = data => java.queryTTF(data);
                    java.replaceFont = function(text, errorFont, correctFont, filter = false) {
                        text = String(text);
                        if (errorFont == null || correctFont == null) return text;
                        if (text.length > 262144) fontFailure('limit_exceeded', 'font replacement text too large');
                        const error = fontObjects.get(errorFont), correct = fontObjects.get(correctFont);
                        if (!error || !correct) throw new TypeError('replaceFont requires queryTTF objects from this context');
                        if (!correct.inverse) {
                            const inverse = new NativeMap();
                            for (const [cp, hash] of correct.characters) {
                                if (hash === false) continue;
                                if (inverse.has(hash) && inverse.get(hash) !== cp) {
                                    fontFailure('unsupported', 'reference font has ambiguous glyph mappings');
                                }
                                inverse.set(hash, cp);
                            }
                            correct.inverse = inverse;
                        }
                        const output = [];
                        for (const char of text) {
                            const cp = char.codePointAt(0);
                            if (fontBlanks.has(cp)) { output.push(char); continue; }
                            const hash = error.characters.get(cp);
                            if (hash === undefined || hash === false) {
                                if (!filter) output.push(char);
                                continue;
                            }
                            const target = correct.inverse.get(hash);
                            output.push(target && String.fromCodePoint(target) || char);
                        }
                        return output.join('');
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
                            catch { stored = String(value); }
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