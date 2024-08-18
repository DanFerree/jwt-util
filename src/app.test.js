// app.test.js
const request = require('supertest');
const { generateRSAKeys, createAndSignJWTWithSecret, createAndSignJWTWithRSA } = require('./jwtUtils');
let app;


const secret = 'your-256-bit-secret';
const payload = { userId: '123', role: 'admin' };

let publicKey, privateKey;

beforeAll(async () => {
    const certPath = 'test/certs';
    const keys = await generateRSAKeys(certPath);
    publicKey = keys.publicKey;
    privateKey = keys.privateKey;
    process.env.CERT_PATH = certPath;
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
