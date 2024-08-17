// jwtUtils.test.js
const { 
    generateRSAKeys, 
    createAndSignJWTWithSecret, 
    createAndSignJWTWithRSA, 
    verifyJWTWithSecret, 
    verifyJWTWithRSA, 
    encryptJWT, 
    decryptJWT 
} = require('./jwtUtils');

describe('JWT Utils', () => {
    let secret;
    let payload;
    let rsaKeys;

    beforeAll(async () => {
        secret = 'your-256-bit-secret';
        payload = { userId: '123', role: 'admin' };
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

    test('should encrypt and decrypt JWT', async () => {
        const token = await createAndSignJWTWithRSA(payload, rsaKeys.privateKey);
        const encryptedToken = await encryptJWT(token, rsaKeys.publicKey);
        expect(encryptedToken).toBeDefined();

        const decryptedToken = await decryptJWT(encryptedToken, rsaKeys.privateKey);
        expect(decryptedToken).toBe(token);
    });
});
