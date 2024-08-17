// symmetricMiddleware.test.js
const express = require('express');
const request = require('supertest');
const symmetricJWTMiddleware = require('./symmetricMiddleware');
const { createAndSignJWTWithSecret } = require('./jwtUtils');

const secret = 'your-256-bit-secret';
const payload = { userId: '123', role: 'admin' };

const app = express();
app.use(symmetricJWTMiddleware(secret));
app.get('/', (req, res) => {
    res.json({ message: 'Symmetric route', payload: req.jwtPayload });
});

describe('Symmetric JWT Middleware', () => {
    let token;

    beforeAll(async () => {
        token = await createAndSignJWTWithSecret(payload, secret);
    });

    test('should allow access with valid token', async () => {
        const res = await request(app)
            .get('/')
            .set('Authorization', `Bearer ${token}`);

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
