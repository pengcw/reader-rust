// Legacy DES compatibility only. EVP operations use the existing host provider.
(() => {
    const specs = new WeakMap(), secretKeys = new WeakMap();
    const fail = message => {
        const error = new Error(message);
        error.kind = 'invalid_argument';
        throw error;
    };
    const bytes = value => {
        if (!Array.isArray(value) && !(value instanceof Uint8Array)) fail('DES byte array required');
        if (value.length > 262144) fail('DES byte array too large');
        return Array.from(value, byte => {
            if (!Number.isInteger(byte) || byte < -128 || byte > 255) fail('invalid DES byte');
            return (byte + 256) % 256;
        });
    };
    function DESKeySpec(value, offset) {
        if (arguments.length < 1 || arguments.length > 2) fail('unsupported DESKeySpec overload');
        const input = bytes(value);
        offset = offset === undefined ? 0 : offset;
        if (!Number.isSafeInteger(offset) || offset < 0 || offset > input.length - 8) fail('DES key requires eight bytes');
        const data = input.slice(offset, offset + 8);
        const object = Object.freeze({getKey: () => data.slice()});
        specs.set(object, data);
        return object;
    }
    const SecretKeyFactory = {
        getInstance(name) {
            if (arguments.length !== 1 || String(name).toUpperCase() !== 'DES') fail('unsupported SecretKeyFactory');
            return Object.freeze({
                getAlgorithm: () => 'DES',
                generateSecret(spec) {
                    const data = specs.get(spec);
                    if (!data) fail('DESKeySpec required');
                    // DES ignores parity bits; normalize odd parity like a DES
                    // secret key factory without changing effective key bits.
                    const key = data.map(byte => {
                        let upper = byte & 254, parity = 0;
                        for (let bit = 1; bit < 8; bit++) parity ^= (upper >> bit) & 1;
                        return upper | (parity ^ 1);
                    });
                    const object = Object.freeze({
                        getEncoded: () => key.slice(), getAlgorithm: () => 'DES', getFormat: () => 'RAW'
                    });
                    secretKeys.set(object, key);
                    return object;
                }
            });
        }
    };
    const original = Packages.javax.crypto.Cipher;
    const Cipher = {
        ENCRYPT_MODE: 1, DECRYPT_MODE: 2,
        getInstance(name) {
            const algorithm = String(name);
            if (!/^DES(?:\/|$)/i.test(algorithm)) return original.getInstance(name);
            if (arguments.length !== 1) fail('unsupported Cipher provider overload');
            const normalized = algorithm.toUpperCase() === 'DES' ? 'DES/ECB/PKCS5PADDING' : algorithm.toUpperCase();
            if (!/^DES\/(ECB|CBC)\/(PKCS5PADDING|PKCS7PADDING|NOPADDING)$/.test(normalized)) fail('unsupported DES transformation');
            let crypto, action;
            return Object.freeze({
                init(mode, key, iv) {
                    if (arguments.length < 2 || arguments.length > 3 || (mode !== 1 && mode !== 2)) fail('invalid DES Cipher init');
                    let data = secretKeys.get(key);
                    // Existing SecretKeySpec facade is also accepted for DES.
                    if (!data && key && String(key.algorithm).toUpperCase() === 'DES') data = bytes(key.key);
                    if (!data || data.length !== 8) fail('DES secret key required');
                    const ivBytes = iv == null ? [] : bytes(iv.iv);
                    const next = java.createSymmetricCrypto(normalized, data, ivBytes);
                    crypto = next;
                    action = mode === 1 ? 'encrypt' : 'decrypt';
                },
                doFinal(value) {
                    if (!crypto) fail('DES Cipher not initialized');
                    if (arguments.length > 1) fail('unsupported DES doFinal overload');
                    return crypto[action](value === undefined ? [] : bytes(value));
                },
                getAlgorithm: () => algorithm
            });
        }
    };
    const mark = (name, value) => {
        Object.defineProperty(value, '__javaName', {value: name});
        return value;
    };
    Packages.javax.crypto.spec.DESKeySpec = mark('DESKeySpec', DESKeySpec);
    Packages.javax.crypto.SecretKeyFactory = mark('SecretKeyFactory', SecretKeyFactory);
    Packages.javax.crypto.Cipher = mark('Cipher', Cipher);
})();
