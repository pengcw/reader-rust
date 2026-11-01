(function(NativeMap) {
                cookie.mapToCookie = function(values) {
                    if (values == null) return null;
                    const pairs = values instanceof NativeMap ? [...values] :
                        (typeof values === 'object' && !Array.isArray(values) ? Object.entries(values) : null);
                    if (pairs === null) throw new TypeError('mapToCookie expects a map');
                    return pairs.length ? pairs.map(([key, value]) =>
                        String(key) + '=' + String(value)).join('; ') : null;
                };
                source.getTag = () => java.getSource()?.bookSourceName ?? null;
                source.getBookSourceUrl = () => source.bookSourceUrl ?? source.getKey();
                source.getConcurrentRate = () => source.concurrentRate ?? null;
                // User-selected compatibility stub: host rate policy is unchanged.
                source.putConcurrent = function() { return true; };
                // Discovery kinds are recomputed per request; there is no result cache to clear.
                source.refreshExplore = function() {};
                let runningSourceLogin = false;
                source.login = function() {
                    if (arguments.length) throw new TypeError('source.login takes no arguments');
                    if (runningSourceLogin) throw new Error('recursive source.login is not supported');
                    runningSourceLogin = true;
                    try {
                        source.__runLogin();
                    } finally {
                        runningSourceLogin = false;
                    }
                };
                let readingSourceHeaders = false;
                source.getHeaderMap = function(hasLoginHeader = false) {
                    if (readingSourceHeaders) throw new Error('recursive source.getHeaderMap');
                    readingSourceHeaders = true;
                    try {
                        return new NativeMap(JSON.parse(source.__getHeaderMap(!!hasLoginHeader)));
                    } finally {
                        readingSourceHeaders = false;
                    }
                };
                source.getLoginInfo = function() {
                    if (globalThis.loginInfo == null) return source.__getLoginInfo() ?? null;
                    return typeof globalThis.loginInfo === 'string'
                        ? globalThis.loginInfo : JSON.stringify(globalThis.loginInfo);
                };
                source.putLoginInfo = function(info) {
                    const raw = String(info);
                    const saved = source.__putLoginInfo(raw);
                    if (saved) globalThis.loginInfo = raw;
                    return saved;
                };
                let initializingLoginInfo = false;
                source.getLoginInfoMap = function() {
                    const raw = source.getLoginInfo();
                    let value = {};
                    if (raw != null) {
                        try { value = JSON.parse(raw); } catch {}
                        if (!value || typeof value !== 'object') value = {};
                    } else if (!initializingLoginInfo) {
                        const rule = String(source.loginUi || '').trim();
                        let ui;
                        try { ui = JSON.parse(rule); } catch {}
                        // V2 defaults belong to the interactive login state, not this Map.
                        if (!(ui && !Array.isArray(ui) && Number(ui.version) === 2) && rule) {
                            initializingLoginInfo = true;
                            const savedBindings = [globalThis.result, globalThis.book, globalThis.chapter];
                            try {
                                const inlineJs = text => {
                                    const match = String(text || '').trim().match(/^(?:@js:([\s\S]*)|<js>([\s\S]*)<\/js>)$/i);
                                    return match ? (match[1] === undefined ? match[2] : match[1]).trim() : null;
                                };
                                const script = inlineJs(rule);
                                if (script !== null) {
                                    globalThis.result = new NativeMap();
                                    globalThis.book = null;
                                    globalThis.chapter = null;
                                    const login = inlineJs(source.loginUrl) ?? String(source.loginUrl || '').trim();
                                    const output = (0, eval)(login + '\n' + script);
                                    try { ui = JSON.parse(output == null ? '' : String(output)); } catch { ui = null; }
                                }
                                if (Array.isArray(ui)) {
                                    const defaults = new NativeMap();
                                    for (const row of ui) {
                                        if (!row || typeof row !== 'object') {
                                            defaults.clear(); break;
                                        }
                                        if (row.type !== 'button') defaults.set(String(row.name ?? ''), String(row.default ?? ''));
                                    }
                                    value = Object.fromEntries(defaults);
                                    if (defaults.size) source.putLoginInfo(JSON.stringify(value));
                                }
                            } finally {
                                [globalThis.result, globalThis.book, globalThis.chapter] = savedBindings;
                                initializingLoginInfo = false;
                            }
                        }
                    }
                    const map = new NativeMap(Object.entries(value).map(([key, item]) => [key, String(item)]));
                    // Preserve the native Map identity and methods. JSON also includes
                    // new properties assigned directly by book-source login scripts.
                    Object.defineProperty(map, 'toJSON', {
                        value: () => Object.fromEntries([...map, ...Object.entries(map)])
                    });
                    for (const key of map.keys()) {
                        if (key in map) continue;
                        Object.defineProperty(map, key, {
                            get: () => map.get(key),
                            set: item => map.set(key, String(item)),
                            configurable: true
                        });
                    }
                    return map;
                };
                java.reGetBook = function() { throw new Error('java.reGetBook is not supported by this host'); };
                java.refreshTocUrl = function() { throw new Error('java.refreshTocUrl is only available in preUpdateJs'); };
                })(globalThis.Map);