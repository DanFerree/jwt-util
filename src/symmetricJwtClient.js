// symmetricJwtClient.js
const axios = require('axios');
const {createSecretKey} = require('crypto');
const { createAndSignJWTWithSecret, symmetricEncryptJWT } = require('./jwtUtils');

// Create an Axios client with symmetric signed and encrypted token
async function createSymmetricAxiosClient(payload, secretString) {
    try {
        const secret = createSecretKey(secretString);
        // console.log('Payload:', payload);
        // console.log('Secret:', secret);

        const token = await createAndSignJWTWithSecret(payload, secret);
        if (!token) {
            throw new Error('Failed to create and sign JWT');
        }

        const encryptedToken = await symmetricEncryptJWT(token, secret);
        if (!encryptedToken) {
            throw new Error('Failed to encrypt JWT');
        }

        const client = axios.create({
            headers: {
                'Authorization': `Bearer ${encryptedToken}`
            }
        });

        return client;
    } catch (error) {
        console.error('Error creating Axios client:', error);
        return undefined;
    }
}

module.exports = createSymmetricAxiosClient;
