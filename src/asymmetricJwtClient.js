// asymmetricJwtClient.js
const axios = require('axios');
const { createAndSignJWTWithRSA, encryptJWT } = require('./jwtUtils');

// Create an Axios client with asymmetric signed and encrypted token
async function createAsymmetricAxiosClient(payload, encryptionPublicKey, signingPrivateKey) {
    const token = await createAndSignJWTWithRSA(payload, signingPrivateKey);
    const encryptedToken = await encryptJWT(token, encryptionPublicKey);

    const client = axios.create({
        headers: {
            Authorization: `Bearer ${encryptedToken}`
        }
    });

    return client;
}

module.exports = createAsymmetricAxiosClient;
