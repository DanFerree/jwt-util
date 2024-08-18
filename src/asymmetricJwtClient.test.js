// asymmetricJwtClient.test.js
const axios = require('axios');
const MockAdapter = require('axios-mock-adapter');
const createAsymmetricAxiosClient = require('./asymmetricJwtClient');
const { generateRSAKeys, createAndSignJWTWithRSA, encryptJWT, decryptJWT, verifyJWTWithRSA } = require('./jwtUtils');

jest.mock('axios');

describe('createAsymmetricAxiosClient', () => {
    const payload = { userId: '123', role: 'admin' };

    let publicKey, privateKey;

    beforeAll(async () => {
        const keys = await generateRSAKeys();
        publicKey = keys.publicKey;
        privateKey = keys.privateKey;
    });

    it('should create an axios client with an asymmetric signed and encrypted token', async () => {
        const mock = new MockAdapter(axios);
        const client = await createAsymmetricAxiosClient(payload, publicKey, privateKey);
        expect(client).toBeDefined();
        
        mock.onGet('/test').reply(async config => {
            const authHeader = config.headers.Authorization;
            const encryptedToken = authHeader.split(' ')[1];

            // Decrypt the token
            const decryptedToken = await decryptJWT(encryptedToken, privateKey);

            // Verify the token
            const verifiedPayload = await verifyJWTWithRSA(decryptedToken, publicKey);

            // Validate the payload
            expect(verifiedPayload).toMatchObject(payload);

            return [200, { message: 'success' }];
        });

        const response = await client.get('/test');

        expect(response.status).toBe(200);
        expect(response.data.message).toBe('success');
    });
});
