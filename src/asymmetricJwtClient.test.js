// asymmetricJwtClient.test.js
const MockAdapter = require('axios-mock-adapter');
const createAsymmetricAxiosClient = require('./asymmetricJwtClient');
const { generateRSAKeys, decryptJWT, verifyJWTWithRSA } = require('./jwtUtils');

describe('createAsymmetricAxiosClient', () => {
    const payload = { userId: '123', role: 'admin' };

    let publicKey, privateKey;

    beforeAll(async () => {
        const keys = await generateRSAKeys();
        publicKey = keys.publicKey;
        privateKey = keys.privateKey;
    });

    it('should create an axios client with an asymmetric signed and encrypted token', async () => {
        const client = await createAsymmetricAxiosClient(payload, publicKey, privateKey);
        expect(client).toBeDefined();
        const mock = new MockAdapter(client);

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
