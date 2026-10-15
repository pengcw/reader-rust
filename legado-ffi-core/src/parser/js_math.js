// Small Java BigInteger surface for rules that explicitly use Packages.java.math.
// Use native QuickJS BigInt; do not round 64-bit source identifiers through Number.
(function() {
    'use strict';
    const MAX_BITS = 4096;

    function bounded(value) {
        if (value.toString(2).replace('-', '').length > MAX_BITS) {
            throw new RangeError('BigInteger exceeds 4096-bit limit');
        }
        return value;
    }

    function fromString(value, radix) {
        if (typeof value !== 'string' || !Number.isInteger(radix) || radix < 2 || radix > 36) {
            throw new TypeError('invalid BigInteger radix or string');
        }
        const sign = value[0] === '-' ? -1n : 1n;
        const digits = value.replace(/^[+-]/, '').toLowerCase();
        if (!digits || digits.length > MAX_BITS) {
            throw new RangeError('invalid or oversized BigInteger string');
        }
        const alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
        let number = 0n;
        for (const digit of digits) {
            const n = alphabet.indexOf(digit);
            if (n < 0 || n >= radix) throw new SyntaxError('invalid BigInteger digits');
            number = bounded(number * BigInt(radix) + BigInt(n));
        }
        return sign * number;
    }

    // The existing JS host adapters represent Java byte[] with signed JS arrays;
    // accept Uint8Array and unsigned 0..255 buffers as well when crossing that boundary.
    function isBytes(value) {
        return Array.isArray(value) ||
            (ArrayBuffer.isView(value) && typeof value.length === 'number');
    }
    function fromMagnitude(bytes) {
        if (bytes.length > MAX_BITS / 8) throw new RangeError('BigInteger byte array too large');
        let raw = 0n;
        for (const byte of bytes) {
            if (!Number.isInteger(byte) || byte < -128 || byte > 255) {
                throw new TypeError('BigInteger requires byte values');
            }
            raw = (raw << 8n) | BigInt(byte & 255);
        }
        return bounded(raw);
    }
    function fromBytes(bytes) {
        if (!bytes.length) throw new RangeError('empty BigInteger byte array');
        const unsigned = fromMagnitude(bytes);
        return (bytes[0] & 128) ? BigInt.asIntN(bytes.length * 8, unsigned) : unsigned;
    }

    class JavaBigInteger {
        constructor(value, radix) {
            if (value instanceof JavaBigInteger && radix === undefined) {
                this._number = value._number;
            } else if (typeof value === 'string') {
                this._number = fromString(value, radix === undefined ? 10 : radix);
            } else if (isBytes(value) && radix === undefined) {
                this._number = fromBytes(value);
            } else if (Number.isInteger(value) && isBytes(radix)) {
                // Java BigInteger(int signum, byte[] magnitude) has distinct
                // signed-magnitude semantics from BigInteger(byte[]).
                if (value < -1 || value > 1) throw new RangeError('invalid BigInteger signum');
                const magnitude = fromMagnitude(radix);
                if (value === 0 && magnitude !== 0n) {
                    throw new RangeError('zero signum with nonzero magnitude');
                }
                this._number = bounded(BigInt(value) * magnitude);
            } else if (typeof value === 'bigint' && radix === undefined) {
                this._number = bounded(value);
            } else {
                throw new TypeError('unsupported BigInteger constructor');
            }
        }
        and(other) { return new JavaBigInteger(bounded(this._number & asBigInt(other))); }
        or(other) { return new JavaBigInteger(bounded(this._number | asBigInt(other))); }
        xor(other) { return new JavaBigInteger(bounded(this._number ^ asBigInt(other))); }
        shiftLeft(bits) { return new JavaBigInteger(bounded(shift(this._number, bits, true))); }
        shiftRight(bits) { return new JavaBigInteger(bounded(shift(this._number, bits, false))); }
        signum() { return this._number < 0n ? -1 : this._number > 0n ? 1 : 0; }
        intValue() { return Number(BigInt.asIntN(32, this._number)); }
        toString(radix = 10) {
            // Java BigInteger.toString falls back to base 10 for invalid radices.
            if (!Number.isInteger(radix) || radix < 2 || radix > 36) radix = 10;
            return this._number.toString(radix);
        }
        toByteArray() {
            if (this._number === 0n) return [0];
            let size = 1;
            if (this._number > 0n) {
                while (this._number >= (1n << BigInt(size * 8 - 1))) size++;
            } else {
                while (this._number < -(1n << BigInt(size * 8 - 1))) size++;
            }
            const unsigned = BigInt.asUintN(size * 8, this._number);
            const bytes = [];
            for (let i = size - 1; i >= 0; i--) {
                bytes.push(Number((unsigned >> BigInt(i * 8)) & 255n));
            }
            return bytes.map(byte => byte > 127 ? byte - 256 : byte);
        }
    }

    function asBigInt(value) {
        if (!(value instanceof JavaBigInteger)) {
            throw new TypeError('expected BigInteger argument');
        }
        return value._number;
    }
    function shift(value, count, left) {
        if (!Number.isInteger(count) || Math.abs(count) > MAX_BITS) {
            throw new RangeError('invalid BigInteger shift');
        }
        return left === (count >= 0)
            ? value << BigInt(Math.abs(count))
            : value >> BigInt(Math.abs(count));
    }

    JavaBigInteger.valueOf = function(value) {
        // Java signature is valueOf(long), not arbitrary-precision JS Number.
        if (typeof value !== 'bigint') {
            if (!Number.isSafeInteger(value)) {
                throw new RangeError('BigInteger.valueOf requires an exact integer');
            }
            value = BigInt(value);
        }
        if (value < -(1n << 63n) || value >= (1n << 63n)) {
            throw new RangeError('BigInteger.valueOf requires a signed 64-bit integer');
        }
        return new JavaBigInteger(value);
    };
    Object.defineProperty(JavaBigInteger, '__javaName', {value: 'BigInteger'});
    Packages.java.math = Packages.java.math || {};
    Packages.java.math.BigInteger = JavaBigInteger;
    // In Legado 'java' is the JsExtensions helper, not a Java package namespace.
})();
