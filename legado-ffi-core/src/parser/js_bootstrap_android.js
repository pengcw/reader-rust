(function() {
                    // Jsoup Element.attr() returns a java.lang.String in Legado's
                    // Rhino bridge; book sources may use its contains(CharSequence).
                    if (typeof String.prototype.contains !== 'function') {
                        Object.defineProperty(String.prototype, 'contains', {
                            value: function(value) { return String(this).includes(String(value)); },
                            writable: true,
                            configurable: true
                        });
                    }
                    const preferenceKey = (name, key) => `__prefs:${String(name)}:${String(key)}`;
                    const sharedPreferences = name => ({
                        getString(key, defaultValue) {
                            const value = source.getVariable(preferenceKey(name, key));
                            return value === '' ? String(defaultValue == null ? '' : defaultValue) : value;
                        },
                        edit() {
                            const changes = {};
                            const editor = {
                                putString(key, value) { changes[String(key)] = String(value); return editor; },
                                remove(key) { changes[String(key)] = null; return editor; },
                                commit() {
                                    for (const [key, value] of Object.entries(changes)) {
                                        source.setVariable(preferenceKey(name, key), value == null ? '' : value);
                                    }
                                    return true;
                                },
                                apply() { editor.commit(); }
                            };
                            return editor;
                        }
                    });
                    const hostContext = {
                        MODE_PRIVATE: 0,
                        getSharedPreferences(name) { return sharedPreferences(name); }
                    };
                    const log = {
                        d(tag, message) { java.log(`[D] ${String(tag)}: ${String(message)}`); return 0; },
                        e(tag, message) { java.log(`[E] ${String(tag)}: ${String(message)}`); return 0; }
                    };
                    const toBytes = value => {
                        if (Array.isArray(value)) return value.map(byte => Number(byte) & 0xff);
                        if (value instanceof Uint8Array) return Array.from(value);
                        return java.strToBytes(String(value == null ? '' : value), 'UTF-8');
                    };
                    java.createSymmetricCrypto = function(transformation, key, iv) {
                        const algorithm = String(transformation == null ? '' : transformation);
                        const upper = algorithm.toUpperCase();
                        // JCA 简写 AES/DES 使用 ECB + PKCS5Padding，复用现有完整实现。
                        const normalized = /^(AES|DES)$/.test(upper)
                            ? upper + '/ECB/PKCS5PADDING' : upper;
                        if (!/^(AES|DES)\/(CBC|ECB)\/(PKCS5PADDING|PKCS7PADDING|NOPADDING)$/.test(normalized)) {
                            throw new Error(
                                'createSymmetricCrypto: unsupported transformation ' + algorithm);
                        }
                        const des = normalized.startsWith('DES/');
                        const symmetricBytes = value => {
                            if (Array.isArray(value) || value instanceof Uint8Array) {
                                return Array.from(value, byte => {
                                    if (!Number.isInteger(byte) || byte < -128 || byte > 255) {
                                        throw new Error('createSymmetricCrypto: invalid byte');
                                    }
                                    return (byte + 256) % 256;
                                });
                            }
                            return toBytes(value);
                        };
                        const keyBytes = symmetricBytes(key);
                        const ivBytes = iv == null ? [] : symmetricBytes(iv);
                        const cbc = normalized.split('/')[1] === 'CBC';
                        const blockSize = des ? 8 : 16;
                        if (!(des ? keyBytes.length === 8 : [16, 24, 32].includes(keyBytes.length))
                            || (cbc ? ivBytes.length !== blockSize : ivBytes.length !== 0)) {
                            throw new Error('createSymmetricCrypto: invalid key or iv');
                        }
                        const native = !des;
                        let capabilities;
                        if (!native) {
                            capabilities = java.hostCall('crypto.capabilities', {});
                            const combination = capabilities && capabilities.symmetric
                                && capabilities.symmetric[normalized];
                            if (!capabilities || capabilities.protocol !== 1 || !combination
                                || !Array.isArray(combination.keyBytes)
                                || !combination.keyBytes.includes(keyBytes.length)
                                || !Number.isSafeInteger(capabilities.maxInputBytes)
                                || capabilities.maxInputBytes < 0) {
                                throw new Error('createSymmetricCrypto: host combination unavailable');
                            }
                        }
                        const invoke = (mode, data) => {
                            const dataBytes = Array.isArray(data) || data instanceof Uint8Array
                                ? symmetricBytes(data)
                                : mode.startsWith('decrypt')
                                    ? JSON.parse(java.__decodeSymmetricInput(String(data == null ? '' : data)))
                                    : symmetricBytes(data);
                            if (!native) {
                                if (dataBytes.length > capabilities.maxInputBytes) {
                                    throw new Error('createSymmetricCrypto: input too large');
                                }
                                const bytes = java.hostCall('crypto.symmetric', {
                                    action: mode, transformation: normalized,
                                    key: keyBytes, iv: ivBytes, data: dataBytes
                                });
                                if (!Array.isArray(bytes) || bytes.length > dataBytes.length + 16
                                    || !bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
                                    throw new Error('createSymmetricCrypto: invalid host byte response');
                                }
                                return bytes;
                            }
                            const nativeLimit = 262144 + (mode === 'decrypt' && !normalized.endsWith('/NOPADDING') ? 16 : 0);
                            if (dataBytes.length > nativeLimit) {
                                const error = new Error('createSymmetricCrypto: input too large');
                                error.kind = 'limit_exceeded'; throw error;
                            }
                            const result = java.__symmetricCrypto(
                                mode,
                                normalized,
                                JSON.stringify(keyBytes),
                                JSON.stringify(ivBytes),
                                JSON.stringify(dataBytes));
                            if (result == null) {
                                const error = new Error('createSymmetricCrypto: invalid block length or padding');
                                error.kind = 'operation_failed'; throw error;
                            }
                            return JSON.parse(result);
                        };
                        return {
                            encrypt(data) {
                                return invoke('encrypt', data);
                            },
                            encryptBase64(data) {
                                return java.__base64EncodeBytes(
                                    JSON.stringify(invoke('encrypt', data)), 2);
                            },
                            encryptHex(data) {
                                return invoke('encrypt', data)
                                    .map(byte => byte.toString(16).padStart(2, '0'))
                                    .join('');
                            },
                            decrypt(data) {
                                return invoke('decrypt', data);
                            },
                            decryptStr(data) {
                                return java.bytesToStr(invoke('decrypt', data), 'UTF-8');
                            }
                        };
                    };
                    const cryptoKeyValue = value => {
                        if (Array.isArray(value) || value instanceof Uint8Array) {
                            if (value.length > 16384) throw new Error('crypto key too large');
                            return Array.from(value, byte => {
                                if (!Number.isInteger(byte) || byte < -128 || byte > 255) {
                                    const error = new Error('invalid crypto key byte');
                                    error.kind = 'invalid_argument'; throw error;
                                }
                                return (byte + 256) % 256;
                            });
                        }
                        const text = String(value == null ? '' : value);
                        if (text.length > 16384) throw new Error('crypto key too large');
                        if (text.includes('-----BEGIN ')) return text;
                        return JSON.parse(java.__base64DecodeBytes(text, 0));
                    };
                    java.createAsymmetricCrypto = function(transformation) {
                        const name = String(transformation == null ? '' : transformation).toUpperCase();
                        const algorithm = name === 'RSA' ? 'RSA/ECB/PKCS1PADDING' : name;
                        if (algorithm !== 'RSA/ECB/PKCS1PADDING') {
                            throw new Error('createAsymmetricCrypto: unsupported transformation');
                        }
                        let publicKey, privateKey, capabilities;
                        const keyValue = cryptoKeyValue;
                        const invoke = (action, data, usePublicKey) => {
                            // Android defaults to PUBLIC for BOTH encrypt and decrypt.
                            const usePublic = usePublicKey === undefined ? true : Boolean(usePublicKey);
                            if ((action === 'decrypt') === usePublic) {
                                const error = new Error('createAsymmetricCrypto: unsupported key direction');
                                error.kind = 'unsupported';
                                throw error;
                            }
                            const key = usePublic ? publicKey : privateKey;
                            if (key == null) throw new Error('createAsymmetricCrypto: selected key is missing');
                            if (!capabilities) capabilities = java.hostCall('crypto.rsa.capabilities', {});
                            if (!capabilities || capabilities.protocol !== 1 || capabilities.available !== true
                                || capabilities.transformation !== algorithm
                                || !Number.isSafeInteger(capabilities.maxInputBytes)
                                || capabilities.maxInputBytes < 0
                                || !Number.isSafeInteger(capabilities.maxEncryptBytes)
                                || capabilities.maxEncryptBytes < 0
                                || !Number.isSafeInteger(capabilities.maxOutputBytes)
                                || capabilities.maxOutputBytes < 0) {
                                throw new Error('createAsymmetricCrypto: host capability unavailable');
                            }
                            const input = action === 'decrypt' && typeof data === 'string'
                                ? JSON.parse(java.__decodeSymmetricInput(data)) : toBytes(data);
                            const limit = action === 'encrypt'
                                ? capabilities.maxEncryptBytes : capabilities.maxInputBytes;
                            if (input.length > limit) {
                                throw new Error('createAsymmetricCrypto: input too large');
                            }
                            const output = java.hostCall('crypto.asymmetric', {
                                action, transformation: algorithm, usePublicKey: usePublic, key, data: input
                            });
                            if (!Array.isArray(output) || output.length > capabilities.maxOutputBytes
                                || !output.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
                                throw new Error('createAsymmetricCrypto: invalid host byte response');
                            }
                            return output;
                        };
                        const object = {
                            setPublicKey(value) { publicKey = keyValue(value); return object; },
                            setPrivateKey(value) { privateKey = keyValue(value); return object; },
                            encrypt(data, usePublicKey) { return invoke('encrypt', data, usePublicKey); },
                            encryptBase64(data, usePublicKey) {
                                return java.__base64EncodeBytes(JSON.stringify(invoke('encrypt', data, usePublicKey)), 2);
                            },
                            encryptHex(data, usePublicKey) {
                                return invoke('encrypt', data, usePublicKey)
                                    .map(byte => byte.toString(16).padStart(2, '0')).join('');
                            },
                            decrypt(data, usePublicKey) { return invoke('decrypt', data, usePublicKey); },
                            decryptStr(data, usePublicKey) {
                                return java.bytesToStr(invoke('decrypt', data, usePublicKey), 'UTF-8');
                            }
                        };
                        return object;
                    };
                    java.createSign = function(algorithm) {
                        const name = String(algorithm == null ? '' : algorithm).toUpperCase();
                        if (name !== 'SHA256WITHRSA') throw new Error('createSign: unsupported algorithm');
                        let privateKey, publicKey;
                        const capabilities = {maxInputBytes:16384,maxSignatureBytes:512};
                        const signatureError = (kind, message) => {
                            const error = new Error('createSign: ' + message);
                            error.kind = kind; return error;
                        };
                        const signatureBytes = value => Array.from(value, byte => {
                            if (!Number.isInteger(byte) || byte < -128 || byte > 255) {
                                const error = new Error('createSign: invalid byte');
                                error.kind = 'invalid_argument'; throw error;
                            }
                            return (byte + 256) % 256;
                        });
                        const invoke = (action, data, signature, charset) => {
                            const key = action === 'sign' ? privateKey : publicKey;
                            if (key == null) throw signatureError('invalid_argument', 'selected key is missing');
                            if (typeof data !== 'string' && !Array.isArray(data) && !(data instanceof Uint8Array)) {
                                throw signatureError('invalid_argument', 'text or byte input required');
                            }
                            if (data.length > capabilities.maxInputBytes) throw signatureError('limit_exceeded', 'input too large');
                            const input = typeof data === 'string'
                                ? java.strToBytes(data, charset == null ? 'UTF-8' : String(charset)) : signatureBytes(data);
                            if (input.length > capabilities.maxInputBytes) throw signatureError('limit_exceeded', 'input too large');
                            let sig;
                            if (action === 'verify') {
                                if (!Array.isArray(signature) && !(signature instanceof Uint8Array)) {
                                    throw signatureError('invalid_argument', 'signature bytes required');
                                }
                                if (signature.length > capabilities.maxSignatureBytes) throw signatureError('limit_exceeded', 'signature too large');
                                sig = signatureBytes(signature);
                            }
                            const response = JSON.parse(java.__signature(JSON.stringify({
                                action, algorithm: name, key, data: input, signature: sig
                            })));
                            if (!response.ok) {
                                const error = new Error(response.error.message);
                                error.kind = response.error.kind; throw error;
                            }
                            const result = response.data;
                            if (action === 'verify') {
                                if (typeof result !== 'boolean') throw new Error('createSign: invalid verification response');
                            } else if (!Array.isArray(result) || result.length < 128
                                || result.length > capabilities.maxSignatureBytes
                                || !result.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
                                throw new Error('createSign: invalid signature response');
                            }
                            return result;
                        };
                        const object = {
                            setPrivateKey(value) { privateKey = cryptoKeyValue(value); return object; },
                            setPublicKey(value) { publicKey = cryptoKeyValue(value); return object; },
                            sign(data, charset) { return invoke('sign', data, undefined, charset); },
                            signHex(data, charset) {
                                return invoke('sign', data, undefined, charset)
                                    .map(byte => byte.toString(16).padStart(2, '0')).join('');
                            },
                            verify(data, signature) { return invoke('verify', data, signature); }
                        };
                        return object;
                    };
                    const archiveInput = value => {
                        if (Array.isArray(value) || value instanceof Uint8Array) {
                            if (value.length > 524288) throw new Error('archive input too large');
                            return toBytes(value);
                        }
                        const text = String(value == null ? '' : value);
                        if (/^https?:\/\//i.test(text)) {
                            const response = JSON.parse(java.__archiveInput(text));
                            if (!response.ok) {
                                const error = new Error(response.error.message);
                                error.kind = response.error.kind; throw error;
                            }
                            return response.data;
                        }
                        if (text.length > 1048576 || text.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(text)) {
                            throw new Error('archive input must be hexadecimal or bytes');
                        }
                        return JSON.parse(java.__hexDecodeBytes(text));
                    };
                    const archiveBytes = (operation, arguments) => {
                        const output = java.hostCall(operation, arguments);
                        if (output === null) return null;
                        if (!Array.isArray(output) || output.length > 262144
                            || !output.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
                            throw new Error('invalid archive byte response');
                        }
                        return output;
                    };
                    java.getZipByteArrayContent = function(input, path) {
                        return archiveBytes('compression.zip.read', {
                            data: archiveInput(input), path: String(path)
                        });
                    };
                    java.getZipStringContent = function(input, path, charset) {
                        const bytes = java.getZipByteArrayContent(input, path);
                        if (bytes === null) return '';
                        const text = java.__decodeArchiveText(
                            JSON.stringify(bytes), charset == null ? '' : String(charset));
                        if (text === null || text === undefined) {
                            const error = new Error('getZipStringContent: invalid bytes or unsupported charset');
                            error.kind = 'invalid_argument';
                            throw error;
                        }
                        return text;
                    };
                    // Project extension: unlike existing ungzip, this returns raw bytes.
                    java.gunzipBytes = function(input) {
                        const response = JSON.parse(java.__gunzipBytes(JSON.stringify(archiveInput(input))));
                        if (!response.ok) {
                            const error = new Error(response.error.message);
                            error.kind = response.error.kind;
                            throw error;
                        }
                        return response.data;
                    };
                    const base64 = {
                        DEFAULT: 0, NO_PADDING: 1, NO_WRAP: 2, CRLF: 4, URL_SAFE: 8,
                        encodeToString(value, flags) {
                            return java.__base64EncodeBytes(
                                JSON.stringify(toBytes(value)), Number(flags || 0));
                        },
                        decode(value, flags) {
                            const input = Array.isArray(value) || value instanceof Uint8Array
                                ? String.fromCharCode(...toBytes(value))
                                : String(value == null ? '' : value);
                            return JSON.parse(java.__base64DecodeBytes(
                                input, Number(flags || 0)));
                        }
                    };
                    const javaBase64Encoder = flags => ({
                        encodeToString(value) { return base64.encodeToString(value, flags); },
                        withoutPadding() { return javaBase64Encoder(flags | base64.NO_PADDING); }
                    });
                    const javaBase64 = {
                        getEncoder() { return javaBase64Encoder(base64.NO_WRAP); },
                        getDecoder() { return { decode: value => base64.decode(value, 0) }; },
                        getUrlEncoder() { return javaBase64Encoder(base64.URL_SAFE | base64.NO_WRAP); },
                        getUrlDecoder() { return { decode: value => base64.decode(value, base64.URL_SAFE) }; }
                    };
                    globalThis.System = Object.assign(globalThis.System || {}, {
                        currentTimeMillis: () => java.now()
                    });
                    const randomUuid = () => {
                        const value = java.randomUUID();
                        return { toString: () => value };
                    };
                    globalThis.UUID = { randomUUID: randomUuid };
                    java.util = java.util || {};
                    java.util.UUID = { randomUUID: randomUuid };
                    java.util.Base64 = javaBase64;

                    if (!String.prototype.getBytes) {
                        Object.defineProperty(String.prototype, 'getBytes', {
                            value(charset) {
                                return java.strToBytes(
                                    String(this), charset == null ? 'UTF-8' : String(charset));
                            }
                        });
                    }

                    const JsString = globalThis.String;
                    const javaStrings = new WeakMap();
                    function JavaString(value, charset) {
                        const text = Array.isArray(value) || value instanceof Uint8Array
                            ? java.bytesToStr(
                                value, charset == null ? 'UTF-8' : JsString(charset))
                            : JsString(value == null ? '' : value);
                        if (!new.target) return text;
                        const wrapped = new JsString(text);
                        javaStrings.set(wrapped, text);
                        return wrapped;
                    }
                    java.__javaStringResult = value => javaStrings.get(value);
                    const streamRange = (bytes, offset, length) => {
                        if (!Array.isArray(bytes) && !(bytes instanceof Uint8Array)) {
                            throw new Error('byte array required');
                        }
                        const start = offset === undefined ? 0 : Number(offset);
                        const count = length === undefined ? bytes.length - start : Number(length);
                        if (!Number.isInteger(start) || !Number.isInteger(count)
                            || start < 0 || count < 0 || start + count > bytes.length) {
                            throw new Error('invalid stream byte range');
                        }
                        return [start, count];
                    };
                    function ByteArrayInputStream(bytes, offset, length) {
                        if (!new.target) return new ByteArrayInputStream(bytes, offset, length);
                        const [start, count] = streamRange(bytes, offset, length);
                        if (count > 524288) throw new Error('stream input too large');
                        this.bytes = toBytes(bytes.slice(start, start + count));
                        this.position = 0;
                        this.markPosition = 0;
                        this.closed = false;
                    }
                    ByteArrayInputStream.prototype = {
                        checkOpen() { if (this.closed) throw new Error('stream is closed'); },
                        read(buffer, offset, length) {
                            this.checkOpen();
                            if (buffer === undefined) {
                                return this.position < this.bytes.length ? this.bytes[this.position++] : -1;
                            }
                            const [start, count] = streamRange(buffer, offset, length);
                            if (count === 0) return 0;
                            if (this.position === this.bytes.length) return -1;
                            const n = Math.min(count, this.bytes.length - this.position);
                            for (let i = 0; i < n; ++i) buffer[start + i] = this.bytes[this.position++];
                            return n;
                        },
                        readAllBytes() {
                            this.checkOpen();
                            const result = this.bytes.slice(this.position);
                            this.position = this.bytes.length;
                            return result;
                        },
                        readNBytes(length) {
                            this.checkOpen();
                            if (!Number.isInteger(length) || length < 0) throw new Error('invalid read length');
                            const result = this.bytes.slice(this.position, this.position + length);
                            this.position += result.length;
                            return result;
                        },
                        available() { this.checkOpen(); return this.bytes.length - this.position; },
                        skip(count) {
                            this.checkOpen();
                            if (!Number.isSafeInteger(count)) throw new Error('invalid skip count');
                            const n = Math.min(Math.max(0, count), this.bytes.length - this.position);
                            this.position += n;
                            return n;
                        },
                        mark() { this.markPosition = this.position; },
                        reset() { this.checkOpen(); this.position = this.markPosition; },
                        markSupported() { return true; },
                        close() {} // JDK ByteArrayInputStream close is a no-op.
                    };
                    function GZIPInputStream(input, size) {
                        if (!new.target) return new GZIPInputStream(input, size);
                        if (!(input instanceof ByteArrayInputStream)) throw new Error('ByteArrayInputStream required');
                        if (size !== undefined && (!Number.isInteger(size) || size <= 0 || size > 262144)) {
                            throw new Error('invalid gzip buffer size');
                        }
                        input.checkOpen();
                        const decoded = java.gunzipBytes(input.bytes.slice(input.position));
                        input.position = input.bytes.length;
                        this.bytes = decoded;
                        this.position = 0;
                        this.closed = false;
                        this.input = input;
                    }
                    GZIPInputStream.prototype = Object.create(ByteArrayInputStream.prototype);
                    Object.assign(GZIPInputStream.prototype, {
                        available() { this.checkOpen(); return this.position < this.bytes.length ? 1 : 0; },
                        markSupported() { return false; },
                        mark() {},
                        reset() { throw new Error('gzip mark/reset is unsupported'); },
                        close() { if (!this.closed) { this.closed = true; this.input.close(); } }
                    });
                    function Inflater(nowrap = false) {
                        if (!new.target) return new Inflater(nowrap);
                        if (typeof nowrap !== 'boolean') throw new Error('boolean nowrap required');
                        this.nowrap = nowrap;
                        this.ended = false;
                    }
                    Inflater.prototype.end = function() { this.ended = true; };
                    function InflaterInputStream(input, inflater, size) {
                        if (!new.target) return new InflaterInputStream(input, inflater, size);
                        if (!(input instanceof ByteArrayInputStream)) throw new Error('ByteArrayInputStream required');
                        if (size !== undefined && (!Number.isInteger(size) || size <= 0 || size > 262144)) {
                            throw new Error('invalid inflater buffer size');
                        }
                        this.ownsInflater = inflater === undefined;
                        inflater = this.ownsInflater ? new Inflater() : inflater;
                        if (!(inflater instanceof Inflater) || inflater.ended) throw new Error('active Inflater required');
                        input.checkOpen();
                        const decode = inflater.nowrap ? java.__inflateRawBytes : java.__inflateZlibBytes;
                        const response = JSON.parse(decode(JSON.stringify(input.bytes.slice(input.position))));
                        if (!response.ok) {
                            const error = new Error(response.error.message);
                            error.kind = response.error.kind; throw error;
                        }
                        input.position = input.bytes.length;
                        this.bytes = response.data;
                        this.position = 0;
                        this.closed = false;
                        this.input = input;
                        this.inflater = inflater;
                    }
                    InflaterInputStream.prototype = Object.create(GZIPInputStream.prototype);
                    Object.assign(InflaterInputStream.prototype, {
                        checkOpen() {
                            ByteArrayInputStream.prototype.checkOpen.call(this);
                            if (this.inflater.ended) throw new Error('inflater is ended');
                        },
                        reset() { throw new Error('inflater mark/reset is unsupported'); },
                        close() {
                            GZIPInputStream.prototype.close.call(this);
                            if (this.ownsInflater) this.inflater.end();
                        }
                    });
                    function ByteArrayOutputStream(size) {
                        if (!new.target) return new ByteArrayOutputStream(size);
                        if (size !== undefined && (!Number.isInteger(size) || size < 0 || size > 262144)) {
                            throw new Error('invalid output stream size');
                        }
                        this.bytes = [];
                    }
                    ByteArrayOutputStream.prototype = {
                        write(value, offset, length) {
                            if (typeof value === 'number') {
                                if (!Number.isInteger(value)) throw new Error('integer byte required');
                                if (this.bytes.length >= 262144) throw new Error('output stream too large');
                                this.bytes.push(value & 255);
                                return;
                            }
                            const [start, count] = streamRange(value, offset, length);
                            if (this.bytes.length + count > 262144) throw new Error('output stream too large');
                            for (let i = 0; i < count; ++i) this.bytes.push(Number(value[start + i]) & 255);
                        },
                        toByteArray() { return this.bytes.slice(); },
                        toString(charset) { return java.bytesToStr(this.bytes, charset == null ? 'UTF-8' : String(charset)); },
                        size() { return this.bytes.length; },
                        reset() { this.bytes = []; },
                        writeTo(stream) { stream.write(this.bytes); },
                        flush() {},
                        close() {} // JDK ByteArrayOutputStream close is a no-op.
                    };
                    // Buffer only until finish/close; compression remains bounded
                    // and is performed by the existing native gzip implementation.
                    function GZIPOutputStream(output) {
                        if (!new.target) return new GZIPOutputStream(output);
                        if (!(output instanceof ByteArrayOutputStream)) {
                            throw new TypeError('ByteArrayOutputStream required');
                        }
                        this.output = output;
                        this.bytes = [];
                        this.finished = false;
                        this.closed = false;
                    }
                    GZIPOutputStream.prototype = {
                        write(value, offset, length) {
                            if (this.finished || this.closed) throw new Error('gzip stream is finished');
                            if (typeof value === 'number') {
                                if (!Number.isInteger(value)) throw new TypeError('integer byte required');
                                if (this.bytes.length >= 262144) throw new Error('gzip input too large');
                                this.bytes.push(value & 255);
                                return;
                            }
                            const [start, count] = streamRange(value, offset, length);
                            if (this.bytes.length + count > 262144) throw new Error('gzip input too large');
                            for (let i = 0; i < count; i++) this.bytes.push(Number(value[start + i]) & 255);
                        },
                        finish() {
                            if (this.finished) return;
                            const response = JSON.parse(java.__gzipBytes(JSON.stringify(this.bytes)));
                            if (!response.ok) {
                                const error = new Error(response.error.message);
                                error.kind = response.error.kind;
                                throw error;
                            }
                            this.output.write(response.data);
                            this.bytes = [];
                            this.finished = true;
                        },
                        flush() { this.output.flush(); },
                        close() {
                            if (this.closed) return;
                            try { this.finish(); }
                            finally { this.closed = true; this.output.close(); }
                        }
                    };
                    function SecureRandom() {
                        if (arguments.length !== 0) throw new TypeError('unsupported SecureRandom constructor');
                        if (!new.target) return new SecureRandom();
                    }
                    SecureRandom.prototype.nextInt = function(bound) {
                        if (arguments.length !== 1 || !Number.isInteger(bound)
                            || bound <= 0 || bound > 2147483647) {
                            throw new TypeError('positive Java int bound required');
                        }
                        return java.__secureRandomNextInt(bound);
                    };
                    function SecretKeySpec(key, algorithm) {
                        const name = JsString(algorithm);
                        return {
                            key: name.toUpperCase() === 'CHACHA20' ? chachaBytes(key, 32) : toBytes(key),
                            algorithm: name
                        };
                    }
                    function IvParameterSpec(iv) {
                        return { iv: toBytes(iv) };
                    }
                    class JavaHashMap extends Map {
                        get(key) { return this.has(key) ? super.get(key) : null; }
                        put(key, value) {
                            const previous = this.get(key);
                            this.set(key, value);
                            return previous;
                        }
                        toJSON() { return Object.fromEntries(this); }
                    }
                    class JavaArrayList extends Array {
                        constructor() {
                            if (arguments.length !== 0) throw new TypeError('unsupported ArrayList constructor');
                            super();
                        }
                        static get [Symbol.species]() { return Array; }
                        add(value) {
                            if (arguments.length !== 1) throw new TypeError('unsupported ArrayList.add overload');
                            this.push(value);
                            return true;
                        }
                        size() {
                            if (arguments.length !== 0) throw new TypeError('ArrayList.size takes no arguments');
                            return this.length;
                        }
                        get(index) {
                            if (arguments.length !== 1 || !Number.isInteger(index) || index < 0 || index >= this.length) {
                                throw new RangeError('ArrayList index out of bounds');
                            }
                            return this[index];
                        }
                    }
                    function JavaLinkedHashMap(values) {
                        if (arguments.length > 1) throw new TypeError('unsupported LinkedHashMap constructor');
                        let entries = [];
                        if (arguments.length === 1) {
                            if (values instanceof Map) entries = values;
                            else if (values && (Object.getPrototypeOf(values) === Object.prototype
                                || Object.getPrototypeOf(values) === null)) entries = Object.entries(values);
                            else throw new TypeError('LinkedHashMap source must be a Map or object');
                        }
                        const map = new JavaHashMap(entries);
                        Object.setPrototypeOf(map, JavaLinkedHashMap.prototype);
                        return map;
                    }
                    Object.setPrototypeOf(JavaLinkedHashMap.prototype, JavaHashMap.prototype);
                    const Arrays = {
                        copyOf(value, length) {
                            if ((!Array.isArray(value) && !(value instanceof Uint8Array))
                                || !Number.isInteger(length) || length < 0 || length > 524288) {
                                throw new Error('invalid byte array copy');
                            }
                            return Arrays.copyOfRange(value, 0, length);
                        },
                        copyOfRange(value, start, end) {
                            const bytes = Array.from(value == null ? [] : value).slice(start, end);
                            while (bytes.length < end - start) bytes.push(0);
                            return bytes;
                        }
                    };
                    const chachaBytes = (value, limit) => {
                        if ((!Array.isArray(value) && !(value instanceof Uint8Array)) || value.length > limit) {
                            throw new TypeError('invalid ChaCha20 byte array');
                        }
                        return Array.from(value, byte => {
                            if (!Number.isInteger(byte) || byte < -128 || byte > 255) {
                                throw new TypeError('invalid ChaCha20 byte');
                            }
                            return byte & 255;
                        });
                    };
                    function GCMParameterSpec(tagBits, nonce) {
                        if (arguments.length !== 2 || tagBits !== 128) {
                            throw new TypeError('only 128-bit authentication tags are supported');
                        }
                        const iv = chachaBytes(nonce, 12);
                        if (iv.length !== 12) throw new TypeError('nonce must be 12 bytes');
                        return {tLen: tagBits, iv};
                    }
                    const chachaCipher = () => {
                        let state = null;
                        return {
                            init(mode, key, parameters) {
                                state = null;
                                if (arguments.length !== 3 || mode !== 2) {
                                    throw new TypeError('only ChaCha20 decryption is supported');
                                }
                                const bytes = chachaBytes(key && key.key, 32);
                                const nonce = chachaBytes(parameters && parameters.iv, 12);
                                if (bytes.length !== 32 || nonce.length !== 12
                                    || JsString(key.algorithm).toUpperCase() !== 'CHACHA20'
                                    || (parameters.tLen !== undefined && parameters.tLen !== 128)) {
                                    throw new TypeError('invalid ChaCha20 parameters');
                                }
                                state = {key: bytes, nonce};
                            },
                            doFinal(data) {
                                if (arguments.length !== 1 || state === null) {
                                    throw new TypeError('ChaCha20 cipher must be initialized; only doFinal(bytes) is supported');
                                }
                                try {
                                    const bytes = chachaBytes(data, 262160);
                                    const output = JSON.parse(java.__chacha20Poly1305Decrypt(JSON.stringify({
                                        key: state.key, nonce: state.nonce, data: bytes
                                    })));
                                    return output.map(byte => byte > 127 ? byte - 256 : byte);
                                } catch (error) {
                                    state = null;
                                    throw error;
                                }
                            }
                        };
                    };
                    const aesGcmCipher = () => {
                        let state = null;
                        return {
                            init(mode, key, parameters) {
                                state = null;
                                if (arguments.length !== 3 || (mode !== 1 && mode !== 2)) {
                                    throw new TypeError('AES-GCM requires encrypt/decrypt mode');
                                }
                                if (!key || JsString(key.algorithm).toUpperCase() !== 'AES'
                                    || !Array.isArray(key.key) || ![16, 32].includes(key.key.length)
                                    || !parameters || parameters.tLen !== 128
                                    || !Array.isArray(parameters.iv) || parameters.iv.length !== 12) {
                                    throw new TypeError('invalid AES-GCM key or parameters');
                                }
                                state = {mode, key: key.key.slice(), nonce: parameters.iv.slice()};
                            },
                            doFinal(data) {
                                if (arguments.length !== 1 || state === null) {
                                    throw new TypeError('AES-GCM cipher must be initialized');
                                }
                                const active = state;
                                state = null;
                                if ((!Array.isArray(data) && !(data instanceof Uint8Array))
                                    || data.length > (active.mode === 1 ? 262144 : 262160)) {
                                    throw new TypeError('invalid AES-GCM byte array');
                                }
                                const bytes = Array.from(data, byte => {
                                    if (!Number.isInteger(byte) || byte < -128 || byte > 255) {
                                        throw new TypeError('invalid AES-GCM byte');
                                    }
                                    return byte & 255;
                                });
                                const output = JSON.parse(java.__aesGcm(JSON.stringify({
                                    mode: active.mode, key: active.key,
                                    nonce: active.nonce, data: bytes
                                })));
                                return output.map(byte => byte > 127 ? byte - 256 : byte);
                            }
                        };
                    };
                    const Cipher = {
                        ENCRYPT_MODE: 1,
                        DECRYPT_MODE: 2,
                        getInstance(algorithm) {
                            if (JsString(algorithm).toUpperCase() === 'AES/GCM/NOPADDING') {
                                if (arguments.length !== 1) throw new TypeError('unsupported AES-GCM provider overload');
                                return aesGcmCipher();
                            }
                            if (JsString(algorithm).toUpperCase() === 'CHACHA20-POLY1305') {
                                if (arguments.length !== 1) throw new TypeError('unsupported ChaCha20 provider overload');
                                return chachaCipher();
                            }
                            return {
                                init(mode, key, iv) { this.mode = mode; this.key = key; this.iv = iv; },
                                doFinal(data) {
                                    const bytes = toBytes(data);
                                    if (bytes.length % 16 !== 0) {
                                        throw new TypeError('AES ciphertext must contain complete blocks');
                                    }
                                    return JSON.parse(java.__aesDecryptByteArray(JSON.stringify({
                                        algorithm, mode: this.mode, key: this.key.key,
                                        iv: this.iv.iv, data: bytes
                                    })));
                                }
                            };
                        }
                    };
                    const Mac = {
                        getInstance: algorithm => ({
                            init(key) { this.key = key; },
                            doFinal(data) {
                                if (String(algorithm).replace(/[^a-z0-9]/gi, '').toUpperCase() === 'HMACMD5') {
                                    const hex = bytes => bytes.map(byte =>
                                        (byte & 255).toString(16).padStart(2, '0')).join('');
                                    return java.hexDecodeToByteArray(java.__hostHmacMd5(
                                        hex(toBytes(this.key ? this.key.key : [])), hex(toBytes(data))));
                                }
                                return JSON.parse(java.__hmacBytes(
                                    String(algorithm),
                                    JSON.stringify(this.key ? this.key.key : []),
                                    JSON.stringify(toBytes(data))));
                            }
                        })
                    };
                    const URLEncoder = {
                        encode(value, charset) {
                            return java.encodeURI(
                                String(value), charset == null ? 'UTF-8' : String(charset))
                                .replace(/%20/g, '+')
                                .replace(/%2A/gi, '*')
                                .replace(/~/g, '%7E');
                        }
                    };
                    const URLDecoder = {
                        decode(value) {
                            return decodeURIComponent(String(value).replace(/\+/g, ' '));
                        }
                    };
                    const DatatypeConverter = {
                        printHexBinary(value) {
                            return toBytes(value)
                                .map(byte => byte.toString(16).padStart(2, '0'))
                                .join('')
                                .toUpperCase();
                        },
                        parseHexBinary(value) {
                            return JSON.parse(java.__hexDecodeBytes(String(value)));
                        }
                    };
                    const markClass = (name, value) => {
                        try {
                            Object.defineProperty(value, '__javaName', {
                                value: name, configurable: true
                            });
                        } catch (_) {}
                        return value;
                    };

                    globalThis.Packages = globalThis.Packages || {};
                    Packages.org = globalThis.org;
                    Packages.java = Packages.java || {};
                    Packages.java.lang = Packages.java.lang || {};
                    Packages.java.net = Packages.java.net || {};
                    Packages.java.io = Packages.java.io || {};
                    Packages.java.nio = Packages.java.nio || {};
                    Packages.java.util = Packages.java.util || {};
                    Packages.java.util.zip = Packages.java.util.zip || {};
                    Packages.javax = Packages.javax || {};
                    Packages.javax.crypto = Packages.javax.crypto || {};
                    Packages.javax.crypto.spec = Packages.javax.crypto.spec || {};
                    Packages.javax.xml = Packages.javax.xml || {};
                    Packages.javax.xml.bind = Packages.javax.xml.bind || {};
                    Packages.android = Packages.android || {};
                    Packages.android.util = Packages.android.util || {};

                    Packages.java.nio.charset = Packages.java.nio.charset || {};
                    // Rhino exposes the Java Charset class; String/byte helpers
                    // below already accept a charset via its string representation.
                    const javaCharsetName = value => {
                        const label = String(value == null ? '' : value).trim();
                        const key = label.toUpperCase().replace(/_/g, '-');
                        const aliases = {
                            'UTF8': 'UTF-8', 'UTF-8': 'UTF-8',
                            'LATIN1': 'ISO-8859-1', 'ISO-8859-1': 'ISO-8859-1',
                            'ISO8859-1': 'ISO-8859-1',
                            'ASCII': 'US-ASCII', 'US-ASCII': 'US-ASCII',
                            'UTF-16': 'UTF-16', 'UTF-16LE': 'UTF-16LE', 'UTF-16BE': 'UTF-16BE',
                            'GBK': 'GBK', 'GB18030': 'GB18030', 'BIG5': 'Big5',
                            'SHIFT-JIS': 'Shift_JIS', 'SJIS': 'Shift_JIS'
                        };
                        const name = aliases[key];
                        if (!name) throw new Error('UnsupportedCharsetException: ' + label);
                        return name;
                    };
                    Packages.java.nio.charset.Charset = markClass('Charset', {
                        forName(value) {
                            const name = javaCharsetName(value);
                            return Object.freeze({ name: () => name, toString: () => name });
                        },
                        isSupported(value) {
                            try { javaCharsetName(value); return true; }
                            catch (_) { return false; }
                        }
                    });
                    Packages.java.nio.ByteBuffer = markClass('ByteBuffer', {
                        allocate(capacity) {
                            if (!Number.isInteger(capacity) || capacity < 0 || capacity > 262144) {
                                throw new Error('invalid byte buffer capacity');
                            }
                            const bytes = new Array(capacity).fill(0);
                            return { array: () => bytes };
                        }
                    });
                    Packages.java.security = Packages.java.security || {};
                    Packages.java.security.SecureRandom = markClass('SecureRandom', SecureRandom);
                    Packages.java.lang.String = markClass('String', JavaString);
                    // Deliberately limited to the string overloads used by source rules.
                    function JavaStringBuilder(initial) {
                        if (arguments.length > 1 || (arguments.length === 1 && typeof initial !== 'string')) {
                            throw new TypeError('StringBuilder supports empty or string construction only');
                        }
                        if (!new.target) return arguments.length === 0
                            ? new JavaStringBuilder() : new JavaStringBuilder(initial);
                        let text = arguments.length === 0 ? '' : initial;
                        const checkSize = size => {
                            if (size > 262144) throw new RangeError('StringBuilder size limit exceeded');
                        };
                        checkSize(text.length);
                        this.append = function(value) {
                            if (arguments.length !== 1 || typeof value !== 'string') {
                                throw new TypeError('StringBuilder.append supports one string only');
                            }
                            checkSize(text.length + value.length);
                            text += value;
                            return this;
                        };
                        this.toString = () => text;
                    }
                    Packages.java.lang.StringBuilder = markClass('StringBuilder', JavaStringBuilder);
                    Packages.java.lang.Integer = markClass('Integer', {
                        toHexString(value) {
                            if (arguments.length !== 1 || !Number.isInteger(value)
                                || value < -2147483648 || value > 2147483647) {
                                throw new TypeError('Integer.toHexString requires a signed 32-bit integer');
                            }
                            return (value >>> 0).toString(16);
                        }
                    });
                    Packages.java.lang.System = markClass('System', globalThis.System);
                    Packages.java.io.ByteArrayInputStream = markClass('ByteArrayInputStream', ByteArrayInputStream);
                    Packages.java.io.ByteArrayOutputStream = markClass('ByteArrayOutputStream', ByteArrayOutputStream);
                    Packages.java.util.zip.GZIPInputStream = markClass('GZIPInputStream', GZIPInputStream);
                    Packages.java.util.zip.GZIPOutputStream = markClass('GZIPOutputStream', GZIPOutputStream);
                    Packages.java.util.zip.Inflater = markClass('Inflater', Inflater);
                    Packages.java.util.zip.InflaterInputStream = markClass('InflaterInputStream', InflaterInputStream);
                    Packages.java.net.URLEncoder = markClass('URLEncoder', URLEncoder);
                    Packages.java.net.URLDecoder = markClass('URLDecoder', URLDecoder);
                    Packages.java.util.Arrays = markClass('Arrays', Arrays);
                    Packages.java.util.HashMap = markClass('HashMap', JavaHashMap);
                    Packages.java.util.ArrayList = markClass('ArrayList', JavaArrayList);
                    Packages.java.util.LinkedHashMap = markClass('LinkedHashMap', JavaLinkedHashMap);
                    Packages.java.util.Base64 = markClass('Base64', javaBase64);
                    Packages.java.util.UUID = markClass('UUID', java.util.UUID);
                    Packages.javax.crypto.Mac = markClass('Mac', Mac);
                    Packages.javax.crypto.Cipher = markClass('Cipher', Cipher);
                    Packages.javax.crypto.spec.SecretKeySpec =
                        markClass('SecretKeySpec', SecretKeySpec);
                    Packages.javax.crypto.spec.IvParameterSpec =
                        markClass('IvParameterSpec', IvParameterSpec);
                    Packages.javax.crypto.spec.GCMParameterSpec =
                        markClass('GCMParameterSpec', GCMParameterSpec);
                    // Rhino-style aliases used by the real decrypt script; java remains the host helper.
                    java.lang = Packages.java.lang;
                    java.nio = Packages.java.nio;
                    java.security = Packages.java.security;
                    globalThis.javax = Packages.javax;
                    Packages.javax.xml.bind.DatatypeConverter =
                        markClass('DatatypeConverter', DatatypeConverter);
                    Packages.android.util.Base64 = markClass('Base64', base64);
                    Packages.android.text = Packages.android.text || {};
                    Packages.android.text.TextUtils = markClass('TextUtils', {
                        isEmpty(value) {
                            if (arguments.length !== 1) throw new TypeError('TextUtils.isEmpty requires one argument');
                            if (value == null) return true;
                            if (typeof value !== 'string' && !(value instanceof JsString)) {
                                throw new TypeError('TextUtils.isEmpty requires a string');
                            }
                            return value.length === 0;
                        }
                    });

                    // Thin URL facade: parsing stays in the existing Rust-backed helper.
                    function JavaURL(spec) {
                        if (!new.target) return new JavaURL(spec);
                        const text = JsString(spec);
                        const parsed = java.toURL(text);
                        Object.defineProperties(this, {
                            host: { value: parsed.host, enumerable: true },
                            path: { value: parsed.pathname, enumerable: true },
                            pathname: { value: parsed.pathname, enumerable: true }
                        });
                        this.toString = () => text;
                    }
                    JavaURL.prototype.getHost = function() { return this.host; };
                    JavaURL.prototype.getPath = function() { return this.path; };
                    Packages.java.net.URL = markClass('URL', JavaURL);
                    const JavaHttpUrl = {
                        parse(spec) {
                            const payload = java.__httpUrl(JsString(spec));
                            if (payload == null) return null;
                            const parsed = JSON.parse(payload);
                            return Object.freeze({
                                host: parsed.host,
                                toString: () => parsed.url,
                                topPrivateDomain() {
                                    const error = new Error('HttpUrl.topPrivateDomain requires public suffix support');
                                    error.kind = 'unsupported';
                                    throw error;
                                }
                            });
                        }
                    };
                    Packages.okhttp3 = Packages.okhttp3 || {};
                    Packages.okhttp3.HttpUrl = markClass('HttpUrl', JavaHttpUrl);

                    // HtmlFormatter.kt at Legado 5198645: regex text formatting,
                    // not DOM extraction, entity decoding, or reader cleaning.
                    const formatHtmlText = (html, indent, keepImages = false) => {
                        if (html === null) return '';
                        if (typeof html !== 'string') throw new TypeError('HtmlFormatter requires string or null');
                        return html
                            .replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\r/g, '\n')
                            .replace(/(&nbsp;)+/g, ' ')
                            .replace(/(&ensp;|&emsp;)/g, ' ')
                            .replace(/(&thinsp;|&zwnj;|&zwj;|\u2009|\u200c|\u200d)/g, '')
                            .replace(/<\/?(?:div|p|br|hr|h\d|article|dd|dl)[^>]*>/g, '\n')
                            .replace(/<!--[^>]*-->/g, '')
                            .replace(keepImages ? /<\/?(?!img)[a-zA-Z]+(?=[ >])[^<>]*>/g
                                : /<\/?[a-zA-Z]+(?=[ >])[^<>]*>/g, '')
                            // Java Pattern's default whitespace is ASCII, unlike JS \s.
                            .replace(/[ \t\n\x0b\f\r]*\n+[ \t\n\x0b\f\r]*/g, '\n' + indent)
                            .replace(/^[\n \t\x0b\f\r]+/g, indent)
                            .replace(/[\n \t\x0b\f\r]+$/g, '');
                    };
                    Packages.io = Packages.io || {};
                    Packages.io.legado = Packages.io.legado || {};
                    Packages.io.legado.app = Packages.io.legado.app || {};
                    Packages.io.legado.app.help = Packages.io.legado.app.help || {};
                    Packages.io.legado.app.help.http = Packages.io.legado.app.help.http || {};
                    Packages.io.legado.app.help.http.StrResponse = markClass('StrResponse', function(url, body) {
                        if (arguments.length !== 2 || typeof url !== 'string' || typeof body !== 'string') {
                            throw new TypeError('StrResponse supports URL and string body only');
                        }
                        let target = 'http://localhost/';
                        try {
                            if (/^https?:\/\//i.test(url) && java.toURL(url).host) target = url;
                        } catch (_) {}
                        return globalThis.__readerMakeStrResponse({url: target, body, code: 200, message: 'OK', headers: {}});
                    });
                    Packages.io.legado.app.utils = Packages.io.legado.app.utils || {};
                    Packages.io.legado.app.utils.HtmlFormatter = markClass('HtmlFormatter', {
                        format(html) {
                            if (arguments.length !== 1) throw new TypeError('HtmlFormatter.format supports one argument');
                            return formatHtmlText(html, '　　');
                        },
                        formatIntro(html) {
                            if (arguments.length !== 1) throw new TypeError('HtmlFormatter.formatIntro requires one argument');
                            return formatHtmlText(html, '');
                        },
                        formatKeepImg(html, redirectUrl) {
                            if (arguments.length < 1 || arguments.length > 2
                                || (redirectUrl != null && !(redirectUrl instanceof JavaURL))) {
                                throw new TypeError('HtmlFormatter.formatKeepImg requires content and optional Java URL');
                            }
                            const formatted = formatHtmlText(html, '　　', true);
                            const image = /<img[^>]*[ \t\n\x0b\f\r]src[ \t\n\x0b\f\r]*=[ \t\n\x0b\f\r]*['"]([^'"{>]*\{(?:[^{}]|\{[^}>]+\})+\})['"][^>]*>|<img[^>]*[ \t\n\x0b\f\r]data-(?:src|original|srcset)[ \t\n\x0b\f\r]*=[ \t\n\x0b\f\r]*['"]([^'">]+)['"][^>]*>|<img[^>]*[ \t\n\x0b\f\r]src[ \t\n\x0b\f\r]*=[ \t\n\x0b\f\r]*"([^">]+)"[^>]*>|<img[^>]*[ \t\n\x0b\f\r](?:data-[^=>]*|src)=[ \t\n\x0b\f\r]*['"]([^'">]*)['"][^>]*>/gi;
                            return formatted.replace(image, (tag, metadata, lazy, quoted, fallback) => {
                                let address = metadata ?? lazy ?? quoted ?? fallback;
                                let param = '';
                                if (metadata !== undefined) {
                                    const separator = /[ \t\n\x0b\f\r]*,[ \t\n\x0b\f\r]*(?=\{)/.exec(address);
                                    if (separator !== null) {
                                        param = ',' + address.slice(separator.index + separator[0].length);
                                        address = address.slice(0, separator.index);
                                    }
                                }
                                address = address.trim();
                                if (redirectUrl != null && !/^(?:[a-z][a-z0-9+.-]*:\/\/|data:)/i.test(address)) {
                                    address = address.startsWith('javascript') ? ''
                                        : java.__jsoupAbsUrl(address, redirectUrl.toString()) || address;
                                }
                                return '<img src="' + address + param + '">';
                            });
                        }
                    });

                    const exposeJavaValue = (target, value) => {
                        if (!value) return;
                        if (value.__javaName) {
                            target[value.__javaName] = value;
                            return;
                        }
                        if (typeof value === 'object') {
                            for (const candidate of Object.values(value)) {
                                if (candidate && candidate.__javaName) {
                                    target[candidate.__javaName] = candidate;
                                }
                            }
                        }
                    };
                    globalThis.JavaImporter = function(...values) {
                        values.forEach(value => exposeJavaValue(this, value));
                        this.importPackage = (...packages) => {
                            packages.forEach(pkg => exposeJavaValue(this, pkg));
                            return this;
                        };
                        this.importClass = this.importPackage;
                    };
                    globalThis.URLEncoder = URLEncoder;
                    globalThis.URLDecoder = URLDecoder;
                    globalThis.Log = log;
                    globalThis.android = globalThis.android || {};
                    globalThis.android.util = globalThis.android.util || {};
                    globalThis.android.util.Log = log;
                    globalThis.android.util.Base64 = base64;
                    globalThis.application = hostContext;
                    globalThis.context = hostContext;
                    globalThis.activity = Object.assign({}, hostContext);
                    globalThis.app = hostContext;
                })();