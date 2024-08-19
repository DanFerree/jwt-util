// symmetricMiddleware.test.js
const express = require('express');
const request = require('supertest');
const {generateSecret} = require('jose');
const symmetricJWTMiddleware = require('./symmetricMiddleware');
const { createAndSignJWTWithSecret, symmetricEncryptJWT } = require('./jwtUtils');

let secret;
const payload = { userId: '123', role: 'admin' };

let app;

describe('Symmetric JWT Middleware', () => {
    let token;

    beforeAll(async () => {
        secret = await generateSecret('A256GCMKW');
        token = await createAndSignJWTWithSecret(payload, secret);
        app = express();
        app.get('/signed', symmetricJWTMiddleware(secret), (req, res) => {
            res.json({ message: 'Symmetric route', payload: req.jwtPayload });
        });
        app.get('/encrypted', symmetricJWTMiddleware(secret, true), (req, res) => {
            res.json({ message: 'Symmetric route', payload: req.jwtPayload });
        });
    });

    test('should allow access with valid token', async () => {
        const res = await request(app)
            .get('/signed')
            .set('Authorization', `Bearer ${token}`);

        expect(res.statusCode).toBe(200);
        expect(res.body.payload).toMatchObject(payload);
    });

    test('should allow access with valid encrypted token', async () => {
        const encrypted = await symmetricEncryptJWT(token, secret);
        const res = await request(app)
            .get('/encrypted')
            .set('Authorization', `Bearer ${encrypted}`);

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
