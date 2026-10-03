// Bounded Java security facade; algorithms stay in the existing Rust helpers.
(() => {
    const specs = new WeakMap();
    const keys = new WeakMap();
    const MAX_KEY = 16384, MAX_DATA = 16384;
    const fail = message => {
        const error = new Error(message);
        error.kind = 'invalid_argument';
        throw error;
    };
    const bytes = (value, limit) => {
        if (!Array.isArray(value) && !(value instanceof Uint8Array)) fail('byte array required');
        if (value.length > limit) fail('byte array too large');
        return Array.from(value, byte => {
            if (!Number.isInteger(byte) || byte < -128 || byte > 255) fail('invalid byte');
            return (byte + 256) % 256;
        });
    };
    // DER container validation only. The crypto provider validates RSA mathematics
    // when using the key; this is not a generic ASN.1 or Java key implementation.
    const reader = data => {
        let position = 0;
        return {
            take(tag) {
                if (data[position++] !== tag) fail('invalid RSA DER tag');
                let length = data[position++];
                if (length === undefined) fail('truncated RSA DER');
                if (length & 128) {
                    const count = length & 127;
                    if (count < 1 || count > 3 || data[position] === 0) fail('invalid RSA DER length');
                    length = 0;
                    for (let i = 0; i < count; i++) {
                        if (position >= data.length) fail('truncated RSA DER length');
                        length = length * 256 + data[position++];
                    }
                    if (length < 128) fail('noncanonical RSA DER length');
                }
                if (position + length > data.length) fail('truncated RSA DER value');
                const result = data.slice(position, position + length);
                position += length;
                return result;
            },
            end() { if (position !== data.length) fail('trailing RSA DER data'); }
        };
    };
    const sequence = data => {
        const outer = reader(data), inner = outer.take(48);
        outer.end();
        return reader(inner);
    };
    const integer = parser => {
        let value = parser.take(2);
        if (!value.length || value[0] & 128
            || (value.length > 1 && value[0] === 0 && !(value[1] & 128))) fail('invalid RSA integer');
        if (value.length > 1 && value[0] === 0) value = value.slice(1);
        return value;
    };
    const zeroVersion = parser => {
        const version = integer(parser);
        if (version.length !== 1 || version[0] !== 0) fail('unsupported RSA key version');
    };
    const algorithm = parser => {
        const encoded = parser.take(48), inner = reader(encoded);
        const oid = inner.take(6);
        if (oid.join(',') !== '42,134,72,134,247,13,1,1,1') fail('RSA key algorithm required');
        if (inner.take(5).length !== 0) fail('invalid RSA algorithm parameters');
        inner.end();
    };
    const validate = (data, privateKey) => {
        const outer = sequence(data);
        if (privateKey) zeroVersion(outer);
        algorithm(outer);
        let payload = outer.take(privateKey ? 4 : 3);
        outer.end();
        if (!privateKey) {
            if (payload[0] !== 0) fail('invalid RSA bit string');
            payload = payload.slice(1);
        }
        const rsa = sequence(payload);
        if (privateKey) zeroVersion(rsa);
        const modulus = integer(rsa), exponent = integer(rsa);
        if (!modulus[0] || !exponent[0]) fail('zero RSA component');
        const bits = (modulus.length - 1) * 8 + (32 - Math.clz32(modulus[0]));
        if (bits < 1024 || bits > 4096 || !(modulus[modulus.length - 1] & 1)) fail('unsupported RSA modulus');
        if (!(exponent[exponent.length - 1] & 1)
            || (exponent.length === 1 && exponent[0] < 3)) fail('invalid RSA exponent');
        if (privateKey) {
            for (let i = 0; i < 6; i++) {
                const component = integer(rsa);
                if (!component[0]) fail('zero RSA private component');
            }
        }
        rsa.end();
    };
    const specConstructor = format => function(value) {
        if (arguments.length !== 1) fail('unsupported KeySpec overload');
        const data = bytes(value, MAX_KEY);
        const object = Object.freeze({
            getEncoded: () => data.slice(),
            getFormat: () => format
        });
        specs.set(object, {format, data});
        return object;
    };
    const PKCS8EncodedKeySpec = specConstructor('PKCS#8');
    const X509EncodedKeySpec = specConstructor('X.509');
    const KeyFactory = {
        getInstance(name) {
            if (arguments.length !== 1) fail('unsupported KeyFactory provider overload');
            if (String(name).toUpperCase() !== 'RSA') fail('unsupported KeyFactory algorithm');
            const generate = (spec, privateKey) => {
                const state = specs.get(spec), format = privateKey ? 'PKCS#8' : 'X.509';
                if (!state || state.format !== format) fail('wrong RSA key spec');
                validate(state.data, privateKey);
                const data = state.data.slice();
                const object = Object.freeze({
                    getEncoded: () => data.slice(),
                    getFormat: () => format,
                    getAlgorithm: () => 'RSA'
                });
                keys.set(object, {privateKey, data});
                return object;
            };
            return Object.freeze({
                getAlgorithm: () => 'RSA',
                generatePrivate: spec => generate(spec, true),
                generatePublic: spec => generate(spec, false)
            });
        }
    };
    const Signature = {
        getInstance(name) {
            if (arguments.length !== 1) fail('unsupported Signature provider overload');
            if (String(name).toUpperCase() !== 'SHA256WITHRSA') fail('unsupported Signature algorithm');
            let mode = null, message = [], signer;
            const initialize = (key, privateKey) => {
                const state = keys.get(key);
                if (!state || state.privateKey !== privateKey) fail('wrong RSA key type');
                const next = java.createSign('SHA256withRSA');
                if (privateKey) next.setPrivateKey(state.data);
                else next.setPublicKey(state.data);
                signer = next;
                mode = privateKey ? 'sign' : 'verify';
                message = [];
            };
            const requireMode = expected => {
                if (!mode || (expected && mode !== expected)) fail('Signature not initialized for operation');
            };
            return Object.freeze({
                getAlgorithm: () => 'SHA256withRSA',
                initSign(key) {
                    if (arguments.length !== 1) fail('unsupported initSign overload');
                    initialize(key, true);
                },
                initVerify(key) {
                    if (arguments.length !== 1) fail('unsupported initVerify overload');
                    initialize(key, false);
                },
                update(value, offset, length) {
                    if (arguments.length !== 1 && arguments.length !== 3) fail('unsupported update overload');
                    requireMode();
                    let chunk;
                    if (typeof value === 'number') {
                        if (offset !== undefined || length !== undefined) fail('invalid update overload');
                        chunk = bytes([value], 1);
                    } else {
                        chunk = bytes(value, MAX_DATA);
                        if (offset !== undefined || length !== undefined) {
                            if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length)
                                || offset < 0 || length < 0 || offset > chunk.length - length) fail('invalid update range');
                            chunk = chunk.slice(offset, offset + length);
                        }
                    }
                    if (message.length + chunk.length > MAX_DATA) fail('Signature message too large');
                    message = message.concat(chunk);
                },
                sign() {
                    if (arguments.length !== 0) fail('unsupported sign overload');
                    requireMode('sign');
                    const result = signer.sign(message);
                    message = [];
                    return result;
                },
                verify(value) {
                    if (arguments.length !== 1) fail('unsupported verify overload');
                    requireMode('verify');
                    const result = signer.verify(message, bytes(value, 512));
                    message = [];
                    return result;
                }
            });
        }
    };
    const digestAlgorithms = new Map([
        ['MD5', ['MD5', 16]], ['SHA1', ['SHA-1', 20]],
        ['SHA256', ['SHA-256', 32]], ['SHA384', ['SHA-384', 48]],
        ['SHA512', ['SHA-512', 64]]
    ]);
    const MessageDigest = {
        getInstance(algorithm) {
            if (arguments.length !== 1) fail('unsupported MessageDigest provider overload');
            const name = String(algorithm).toUpperCase().replace(/^SHA-/, 'SHA');
            const entry = digestAlgorithms.get(name);
            if (!entry) fail('unsupported MessageDigest algorithm');
            const [canonical, length] = entry;
            let message = [];
            const append = chunk => {
                if (message.length + chunk.length > MAX_DATA) fail('MessageDigest message too large');
                return message.concat(chunk);
            };
            return Object.freeze({
                getAlgorithm() {
                    if (arguments.length) fail('unsupported getAlgorithm overload');
                    return canonical;
                },
                getDigestLength() {
                    if (arguments.length) fail('unsupported getDigestLength overload');
                    return length;
                },
                update(value, offset, length) {
                    if (arguments.length !== 1 && arguments.length !== 3) fail('unsupported update overload');
                    let chunk;
                    if (typeof value === 'number') {
                        if (arguments.length !== 1) fail('unsupported byte update overload');
                        chunk = bytes([value], 1);
                    } else {
                        chunk = bytes(value, MAX_DATA);
                        if (arguments.length === 3) {
                            if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length)
                                || offset < 0 || length < 0 || offset > chunk.length - length) fail('invalid update range');
                            chunk = chunk.slice(offset, offset + length);
                        }
                    }
                    message = append(chunk);
                },
                reset() {
                    if (arguments.length) fail('unsupported reset overload');
                    message = [];
                },
                digest(value) {
                    if (arguments.length > 1) fail('unsupported digest overload');
                    const input = arguments.length ? append(bytes(value, MAX_DATA)) : message;
                    const result = java.__digestBytes(input, canonical);
                    if (result == null) fail('MessageDigest computation failed');
                    message = [];
                    return result;
                }
            });
        }
    };
    const mark = (name, value) => {
        Object.defineProperty(value, '__javaName', {value: name});
        return value;
    };
    Packages.java.security = Packages.java.security || {};
    Packages.java.security.spec = Packages.java.security.spec || {};
    Packages.java.security.MessageDigest = mark('MessageDigest', MessageDigest);
    Packages.java.security.Signature = mark('Signature', Signature);
    Packages.java.security.KeyFactory = mark('KeyFactory', KeyFactory);
    Packages.java.security.spec.PKCS8EncodedKeySpec = mark('PKCS8EncodedKeySpec', PKCS8EncodedKeySpec);
    Packages.java.security.spec.X509EncodedKeySpec = mark('X509EncodedKeySpec', X509EncodedKeySpec);
})();
