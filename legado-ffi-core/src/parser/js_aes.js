// Legado 5198645: standard AES wrappers delegate to the shared cipher.
(function () {
    const cipher = (data, key, transformation, iv) => {
        if (![data, key, transformation, iv].every(value => typeof value === 'string')) {
            throw new TypeError('AES wrappers require data, key, transformation and iv strings');
        }
        return java.createSymmetricCrypto(transformation, key, iv);
    };
    java.aesDecodeToByteArray = (data, key, transformation, iv) =>
        cipher(data, key, transformation, iv).decrypt(data);
    java.aesBase64DecodeToByteArray = java.aesDecodeToByteArray;
    java.aesDecodeToString = (data, key, transformation, iv) =>
        cipher(data, key, transformation, iv).decryptStr(data);
    java.aesBase64DecodeToString = java.aesDecodeToString;
    java.aesEncodeToByteArray = (data, key, transformation, iv) =>
        cipher(data, key, transformation, iv).encrypt(data);
    java.aesEncodeToBase64String = (data, key, transformation, iv) =>
        cipher(data, key, transformation, iv).encryptBase64(data);
    java.aesEncodeToBase64ByteArray = (data, key, transformation, iv) =>
        java.strToBytes(java.aesEncodeToBase64String(data, key, transformation, iv), 'UTF-8');
    // Explicit legado-full e02de80 compatibility choice: return encrypted Base64.
    // This differs from Legado 5198645, whose same-named wrapper decrypts.
    java.aesEncodeToString = java.aesEncodeToBase64String;
})();
