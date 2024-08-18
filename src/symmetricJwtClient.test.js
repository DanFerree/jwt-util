// symmetricJwtClient.test.js
const axios = require('axios');
const MockAdapter = require('axios-mock-adapter');
const createSymmetricAxiosClient = require('./symmetricJwtClient');
const { createAndSignJWTWithSecret, encryptJWT, decryptJWT, verifyJWTWithSecret, convertSecretToUint8Array } = require('./jwtUtils');

jest.mock('axios');

describe('createSymmetricAxiosClient', () => {
    const secret = 'your-256-bit-secret';
    const payload = { userId: '123', role: 'admin' };

    it('should create an axios client with a symmetric signed and encrypted token', async () => {
        const mock = new MockAdapter(axios);
        const client = await createSymmetricAxiosClient(payload, secret);

        mock.onGet('/test').reply(config => {
            const authHeader = config.headers.Authorization;
            const encryptedToken = authHeader.split(' ')[1];

            // Decrypt the token
            const decryptedToken = decryptJWT(encryptedToken, convertSecretToUint8Array(secret));

            // Verify the token
            const verifiedPayload = verifyJWTWithSecret(decryptedToken, secret);

            // Validate the payload
            expect(verifiedPayload).toMatchObject(payload);

            return [200, { message: 'success' }];
        });

        const response = await client.get('/test');

        expect(response.status).toBe(200);
        expect(response.data.message).toBe('success');
    });
});
