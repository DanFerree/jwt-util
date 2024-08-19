// asymmetricMiddleware.test.js
const express = require('express');
const request = require('supertest');
const asymmetricJWTMiddleware = require('./asymmetricMiddleware');
const { generateRSAKeys, createAndSignJWTWithRSA, asymmetricEncryptJWT } = require('./jwtUtils');

const payload = { userId: '123', role: 'admin' };

let signingPublicKey, encryptionPrivateKey;

const app = express();

beforeAll(async () => {
    const keys = await generateRSAKeys();
    signingPublicKey = keys.publicKey;
    encryptionPrivateKey = keys.privateKey;
    app.get('/signed', asymmetricJWTMiddleware(signingPublicKey, null), (req, res) => {
        res.json({ message: 'Asymmetric route', payload: req.jwtPayload });
    });
    app.get('/encrypted', asymmetricJWTMiddleware(signingPublicKey, encryptionPrivateKey), (req, res) => {
        res.json({ message: 'Asymmetric route', payload: req.jwtPayload });
    });
});

describe('Asymmetric JWT Middleware', () => {
    let token;

    beforeAll(async () => {
        token = await createAndSignJWTWithRSA(payload, encryptionPrivateKey);
    });

    test('should allow access with valid unencrypted token', async () => {
        const res = await request(app)
            .get('/signed')
            .set('Authorization', `Bearer ${token}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.payload).toMatchObject(payload);
    });

    test('should allow access with valid encrypted token', async () => {
        const encToken = await asymmetricEncryptJWT(token, signingPublicKey);
        const res = await request(app)
            .get('/encrypted')
            .set('Authorization', `Bearer ${encToken}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.payload).toMatchObject(payload);
    });

    test('should deny access with invalid token', async () => {
        const res = await request(app)
            .get('/signed')
            .set('Authorization', 'Bearer invalidtoken');

        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('Invalid token');
    });

    test('should deny access without token', async () => {
        const res = await request(app).get('/signed');

        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('No token provided');
    });
});
