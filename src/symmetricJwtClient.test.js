// symmetricJwtClient.test.js
const axios = require('axios');
const crypto = require('crypto');
const { generateSecret } = require('jose');
const MockAdapter = require('axios-mock-adapter');
const createSymmetricAxiosClient = require('./symmetricJwtClient');
const { decryptJWT, verifyJWTWithSecret, convertSecretToUint8Array } = require('./jwtUtils');
const secretString = 'abcdefghijklmopqrstuvwxyzABCDEFG';

jest.mock('axios');

describe('createSymmetricAxiosClient', () => {
    let secret;
    let payload;

    beforeAll(async () => {
        payload = { userId: '123', role: 'admin' };
        secret = crypto.createSecretKey(secretString);
    });

    it('should create an axios client with a symmetric signed and encrypted token', async () => {
        const mock = new MockAdapter(axios);
        const client = await createSymmetricAxiosClient(payload, secretString);
        expect(client).toBeDefined();

        mock.onGet('/test').reply(config => {
            const authHeader = config.headers.Authorization;
            const encryptedToken = authHeader.split(' ')[1];

            // Decrypt the token
            const decryptedToken = decryptJWT(encryptedToken, secret);

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
