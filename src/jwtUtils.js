// jwtUtils.js
const {
    SignJWT,
    jwtVerify,
    generateKeyPair,
    CompactEncrypt,
    compactDecrypt,
    importSPKI,
    importPKCS8,
    exportJWK,
    importJWK
} = require('jose');

// Generate RSA key pair for asymmetric encryption and/or signing
async function generateRSAKeys() {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    return { publicKey, privateKey };
}

async function keysToPem({ privateKey, publicKey }) {
    // Convert keys to PEM format
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    return { publicPem, privatePem };
}

async function readKeys({ publicPem, privatePem }) {
    // Import keys
    const publicKey = await importSPKI(publicPem, 'RS256');
    const privateKey = await importPKCS8(privatePem, 'RS256');

    return { publicKey, privateKey };
}

// Convert secret to Uint8Array
function convertSecretToUint8Array(secret) {
    return new TextEncoder().encode(secret);
}

function uint8ArrayToBase64(uint8Array) {
    return Buffer.from(uint8Array).toString('base64');
}

function base64ToUint8Array(base64String) {
    return new Uint8Array(Buffer.from(base64String, 'base64'));
}

async function exportSecretKeyToString(secretKey) {
    const jwk = await exportJWK(secretKey);
    return JSON.stringify(jwk);
}

async function importStringToSecretKey(jwkString) {
    const jwk = JSON.parse(jwkString);
    const secretKey = await importJWK(jwk, 'A256GCMKW'); // HS256
    return secretKey;
}


// Create and sign a JWT (symmetric)
async function createAndSignJWTWithSecret(payload, secret) {
    const secretKey = convertSecretToUint8Array(secret);
    const jwt = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('2h')
        .sign(secretKey);
    return jwt;
}

// Create and sign a JWT (asymmetric)
async function createAndSignJWTWithRSA(payload, privateKey, expiration = '3m') {
    const jwt = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256' })
        .setIssuedAt()
        .setExpirationTime(expiration)
        .sign(privateKey);
    return jwt;
}

// Verify a JWT (symmetric)
async function verifyJWTWithSecret(token, secret) {
    const secretKey = convertSecretToUint8Array(secret);
    const { payload } = await jwtVerify(token, secretKey);
    return payload;
}

// Verify a JWT (asymmetric)
async function verifyJWTWithRSA(token, publicKey) {
    const { payload } = await jwtVerify(token, publicKey);
    return payload;
}

async function symmetricEncryptJWT(jwt, secret) {
    const encoder = new TextEncoder();
    // const secretKey = encoder.encode(secret);
    const jwe = await new CompactEncrypt(encoder.encode(jwt))
        .setProtectedHeader({ alg: 'A256GCMKW', enc: 'A256GCM' })
        .encrypt(secret);
    return jwe;
}

// Encrypt a JWT (asymmetric)
async function asymmetricEncryptJWT(jwt, publicKey) {
    const encoder = new TextEncoder();
    const jwe = await new CompactEncrypt(encoder.encode(jwt))
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
        .encrypt(publicKey);
    return jwe;
}

// Decrypt a JWT (asymmetric)
async function decryptJWT(jwe, privateKey) {
    const { plaintext } = await compactDecrypt(jwe, privateKey);
    return new TextDecoder().decode(plaintext);
}


module.exports = {
    generateRSAKeys,
    keysToPem,
    readKeys,
    convertSecretToUint8Array,
    createAndSignJWTWithSecret,
    createAndSignJWTWithRSA,
    verifyJWTWithSecret,
    verifyJWTWithRSA,
    symmetricEncryptJWT,
    asymmetricEncryptJWT,
    decryptJWT,
    exportSecretKeyToString,
    importStringToSecretKey,
    uint8ArrayToBase64,
    base64ToUint8Array
};
