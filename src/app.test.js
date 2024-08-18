// app.test.js
const request = require('supertest');
const crypto = require('crypto');
const { generateSecret } = require('jose');
const { 
    generateRSAKeys, 
    createAndSignJWTWithSecret, 
    createAndSignJWTWithRSA,
    symmetricEncryptJWT,
    asymmetricEncryptJWT, 
    keysToPem,
    convertSecretToUint8Array,
    exportSecretKeyToString
} = require('./jwtUtils');
let app;


const payload = { userId: '123', role: 'admin' };
const secretString = 'abcdefghijklmopqrstuvwxyzABCDEFG';
let secret, publicKey, privateKey;

beforeAll(async () => {
    const keys = await generateRSAKeys();
    publicKey = keys.publicKey;
    privateKey = keys.privateKey;
    const {publicPem, privatePem } = await keysToPem(keys);
    secret = crypto.createSecretKey(secretString);
    process.env.SHARED_SECRET = secretString;
    process.env.CLIENT_PUBLIC = publicPem;
    process.env.SERVER_PRIVATE = privatePem;
    app = require('./app'); // Assuming app.js exports the app instance
});

describe('JWT Middleware', () => {
    let symmetricToken;
    let asymmetricToken;

    beforeAll(async () => {
        symmetricToken = await createAndSignJWTWithSecret(payload, secret);
        asymmetricToken = await createAndSignJWTWithRSA(payload, privateKey);
    });

    test('should allow access to symmetric route with valid token', async () => {
        const res = await request(app)
            .get('/symmetric')
            .set('Authorization', `Bearer ${symmetricToken}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.payload).toMatchObject(payload);
    });

    test('should allow access to symmetric route with valid encrypted token', async () => {
    console.log('secret: ', secret)

        const encrypted = await symmetricEncryptJWT(symmetricToken, secret)
        const res = await request(app)
            .get('/symmetric')
            .set('Authorization', `Bearer ${encrypted}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.payload).toMatchObject(payload);
    });

    test('should deny access to symmetric route with invalid token', async () => {
        const res = await request(app)
            .get('/symmetric')
            .set('Authorization', 'Bearer invalidtoken');

        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('Invalid token');
    });

    test('should deny access to symmetric route without token', async () => {
        const res = await request(app).get('/symmetric');

        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('No token provided');
    });

    test('should allow access to asymmetric route with valid token', async () => {
        const res = await request(app)
            .get('/asymmetric')
            .set('Authorization', `Bearer ${asymmetricToken}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.payload).toMatchObject(payload);
    });

    test('should allow access to asymmetric route with valid encrypted token', async () => {
        const encrypted = await asymmetricEncryptJWT(asymmetricToken, publicKey)
        const res = await request(app)
            .get('/asymmetric')
            .set('Authorization', `Bearer ${encrypted}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.payload).toMatchObject(payload);
    });

    test('should deny access to asymmetric route with invalid token', async () => {
        const res = await request(app)
            .get('/asymmetric')
            .set('Authorization', 'Bearer invalidtoken');

        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('Invalid token');
    });

    test('should deny access to asymmetric route without token', async () => {
        const res = await request(app).get('/asymmetric');

        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('No token provided');
    });
});
