// asymmetricMiddleware.test.js
const express = require('express');
const request = require('supertest');
const asymmetricJWTMiddleware = require('./asymmetricMiddleware');
const { generateRSAKeys, createAndSignJWTWithRSA, asymmetricEncryptJWT } = require('./jwtUtils');

const payload = { userId: '123', role: 'admin' };

let publicKey, privateKey;

const app = express();

beforeAll(async () => {
    const keys = await generateRSAKeys();
    publicKey = keys.publicKey;
    privateKey = keys.privateKey;
    app.use(asymmetricJWTMiddleware(publicKey, privateKey));
    app.get('/', (req, res) => {
        res.json({ message: 'Asymmetric route', payload: req.jwtPayload });
    });
});

describe('Asymmetric JWT Middleware', () => {
    let token;

    beforeAll(async () => {
        token = await createAndSignJWTWithRSA(payload, privateKey);
    });

    test('should allow access with valid unencrypted token', async () => {
        const res = await request(app)
            .get('/')
            .set('Authorization', `Bearer ${token}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.payload).toMatchObject(payload);
    });

    test('should allow access with valid encrypted token', async () => {
        const encToken = await asymmetricEncryptJWT(token, publicKey);
        const res = await request(app)
            .get('/')
            .set('Authorization', `Bearer ${encToken}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.payload).toMatchObject(payload);
    });

    test('should deny access with invalid token', async () => {
        const res = await request(app)
            .get('/')
            .set('Authorization', 'Bearer invalidtoken');

        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('Invalid token');
    });

    test('should deny access without token', async () => {
        const res = await request(app).get('/');

        expect(res.statusCode).toBe(401);
        expect(res.body.error).toBe('No token provided');
    });
});
