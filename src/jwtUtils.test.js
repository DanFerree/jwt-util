// jwtUtils.test.js
const { generateSecret } = require('jose');
const crypto = require('crypto');
const { 
    generateRSAKeys, 
    createAndSignJWTWithSecret, 
    createAndSignJWTWithRSA, 
    verifyJWTWithSecret, 
    verifyJWTWithRSA,
    symmetricEncryptJWT, 
    asymmetricEncryptJWT, 
    decryptJWT 
} = require('./jwtUtils');

describe('JWT Utils', () => {
    let secret;
    let payload;
    let rsaKeys;

    beforeAll(async () => {
        payload = { userId: '123', role: 'admin' };
        // secret = await generateSecret('A256GCMKW');
        secret = crypto.createSecretKey('abcdefghijklmopqrstuvwxyzABCDEFG');
        rsaKeys = await generateRSAKeys();
    });

    test('should create and verify JWT with secret', async () => {
        const token = await createAndSignJWTWithSecret(payload, secret);
        expect(token).toBeDefined();

        const verifiedPayload = await verifyJWTWithSecret(token, secret);
        expect(verifiedPayload).toMatchObject(payload);
    });

    test('should create and verify JWT with RSA keys', async () => {
        const token = await createAndSignJWTWithRSA(payload, rsaKeys.privateKey);
        expect(token).toBeDefined();

        const verifiedPayload = await verifyJWTWithRSA(token, rsaKeys.publicKey);
        expect(verifiedPayload).toMatchObject(payload);
    });

    test('should asymmetric encrypt and decrypt JWT', async () => {
        const token = await createAndSignJWTWithRSA(payload, rsaKeys.privateKey);
        const encryptedToken = await asymmetricEncryptJWT(token, rsaKeys.publicKey);
        expect(encryptedToken).toBeDefined();

        const decryptedToken = await decryptJWT(encryptedToken, rsaKeys.privateKey);
        expect(decryptedToken).toBe(token);

        const verifiedPayload = await verifyJWTWithRSA(token, rsaKeys.publicKey);
        expect(verifiedPayload).toMatchObject(payload); 
    });

    test('should symmetric encrypt and decrypt JWT', async () => {
        const token = await createAndSignJWTWithSecret(payload, secret);
        const encryptedToken = await symmetricEncryptJWT(token, secret);
        expect(encryptedToken).toBeDefined();

        const decryptedToken = await decryptJWT(encryptedToken, secret);
        expect(decryptedToken).toBe(token);

        const verifiedPayload = await verifyJWTWithSecret(token, secret);
        expect(verifiedPayload).toMatchObject(payload);
    });
});
