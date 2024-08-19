// symmetricJwtClient.test.js
const crypto = require('crypto');
const MockAdapter = require('axios-mock-adapter');
const createSymmetricAxiosClient = require('./symmetricJwtClient');
const { decryptJWT, verifyJWTWithSecret } = require('./jwtUtils');
const secretString = 'abcdefghijklmopqrstuvwxyzABCDEFG';

// jest.mock('axios');

describe('createSymmetricAxiosClient', () => {
    let secret;
    let payload;

    beforeAll(async () => {
        payload = { userId: '123', role: 'admin' };
        secret = crypto.createSecretKey(secretString);
    });

    it('should create an axios client with a symmetric signed and encrypted token', async () => {
        const client = await createSymmetricAxiosClient(payload, secretString);
        expect(client).toBeDefined();
        const mock = new MockAdapter(client);

        mock.onGet('/test').reply(async config => {
            const authHeader = config.headers.Authorization;
            const encryptedToken = authHeader.split(' ')[1];

            // Decrypt the token
            const decryptedToken = await decryptJWT(encryptedToken, secret);

            // Verify the token
            const verifiedPayload = await verifyJWTWithSecret(decryptedToken, secret);

            // Validate the payload
            expect(verifiedPayload).toMatchObject(payload);

            return [200, { message: 'success' }];
        });

        const response = await client.get('/test');

        expect(response.status).toBe(200);
        expect(response.data.message).toBe('success');
    });
});
