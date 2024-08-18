// asymmetricJwtClient.js
const axios = require('axios');
const { createAndSignJWTWithRSA, asymmetricEncryptJWT } = require('./jwtUtils');

// Create an Axios client with asymmetric signed and encrypted token
async function createAsymmetricAxiosClient(payload, encryptionPublicKey, signingPrivateKey) {
    const token = await createAndSignJWTWithRSA(payload, signingPrivateKey);
    const encryptedToken = await asymmetricEncryptJWT(token, encryptionPublicKey);

    const client = await axios.create({
        headers: {
            Authorization: `Bearer ${encryptedToken}`
        }
    });

    return client;
}

module.exports = createAsymmetricAxiosClient;
