// jwtUtils.js
const { SignJWT, jwtVerify, generateKeyPair, CompactEncrypt, compactDecrypt, JWK } = require('jose');

// Generate RSA key pair for asymmetric encryption
async function generateRSAKeys() {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    return { publicKey, privateKey };
}

// Convert secret to Uint8Array
function convertSecretToUint8Array(secret) {
    return new TextEncoder().encode(secret);
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
async function createAndSignJWTWithRSA(payload, privateKey) {
    const jwt = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256' })
        .setIssuedAt()
        .setExpirationTime('2h')
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

// Encrypt a JWT (asymmetric)
async function encryptJWT(jwt, publicKey) {
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
    createAndSignJWTWithSecret,
    createAndSignJWTWithRSA,
    verifyJWTWithSecret,
    verifyJWTWithRSA,
    encryptJWT,
    decryptJWT
};
