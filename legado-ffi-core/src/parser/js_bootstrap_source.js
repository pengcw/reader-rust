(function(NativeMap) {
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
                        try { value = JSON.parse(raw); } catch (_) {}
                        if (!value || typeof value !== 'object') value = {};
                    } else if (!initializingLoginInfo) {
                        const rule = String(source.loginUi || '').trim();
                        let ui;
                        try { ui = JSON.parse(rule); } catch (_) {}
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
                                    try { ui = JSON.parse(output == null ? '' : String(output)); } catch (_) { ui = null; }
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
                    // Config keys supplement, never shadow, native Map members.
                    for (const key of map.keys()) {
                        if (key in map) continue;
                        Object.defineProperty(map, key, {
                            get: () => map.get(key),
                            configurable: true
                        });
                    }
                    return map;
                };
                java.reGetBook = function() { throw new Error('java.reGetBook is not supported by this host'); };
                java.refreshTocUrl = function() { throw new Error('java.refreshTocUrl is only available in preUpdateJs'); };
                })(globalThis.Map);