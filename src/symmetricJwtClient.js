// symmetricJwtClient.js
const axios = require('axios');
const { createAndSignJWTWithSecret, encryptJWT, convertSecretToUint8Array } = require('./jwtUtils');

// Create an Axios client with symmetric signed and encrypted token
async function createSymmetricAxiosClient(payload, secret) {
    const token = await createAndSignJWTWithSecret(payload, secret);
    // const encryptedToken = await encryptJWT(token, convertSecretToUint8Array(secret));
    //TODO: need symmetric encryption with secret
    const client = axios.create({
        headers: {
            Authorization: `Bearer ${token}`
        }
    });

    return client;
}

module.exports = createSymmetricAxiosClient;
