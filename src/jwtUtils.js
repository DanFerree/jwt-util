// jwtUtils.js
const fs = require('fs').promises;
const path = require('path');
const { 
    SignJWT, 
    jwtVerify, 
    generateKeyPair, 
    CompactEncrypt, 
    compactDecrypt, 
    importSPKI, 
    importPKCS8
 } = require('jose');

// Generate RSA key pair for asymmetric encryption
async function generateRSAKeys(dirPath, name) {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    if (dirPath) {
        // Convert keys to PEM format
        const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
        const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

        // Write keys to files
        await fs.writeFile(path.join(dirPath, name ? `${name}-public.pem` : 'publicKey.pem'), publicKeyPem);
        await fs.writeFile(path.join(dirPath, name ? `${name}-private.pem` : 'privateKey.pem'), privateKeyPem);
        // console.log('Keys have been written to files.');
    }
    return { publicKey, privateKey };
}

async function readKeys(dirPath = __dirname, name) {
    // Read keys from files
    const publicKeyPem = await fs.readFile(path.join(dirPath, name ? `${name}-public.pem` : 'publicKey.pem'), 'utf8');
    const privateKeyPem = await fs.readFile(path.join(dirPath, name ? `${name}-private.pem` : 'privateKey.pem'), 'utf8');

    // Import keys
    const publicKey = await importSPKI(publicKeyPem, 'RS256');
    const privateKey = await importPKCS8(privateKeyPem, 'RS256');

    console.log('Keys have been read from files and imported.');
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
    readKeys,
    convertSecretToUint8Array,
    createAndSignJWTWithSecret,
    createAndSignJWTWithRSA,
    verifyJWTWithSecret,
    verifyJWTWithRSA,
    encryptJWT,
    decryptJWT
};
