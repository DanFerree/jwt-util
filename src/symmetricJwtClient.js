// symmetricJwtClient.js
const axios = require('axios');
const {createSecretKey} = require('crypto');
const { createAndSignJWTWithSecret, symmetricEncryptJWT, convertSecretToUint8Array } = require('./jwtUtils');

// Create an Axios client with symmetric signed and encrypted token
async function createSymmetricAxiosClient(payload, secretString) {
    try {
        const secret = createSecretKey(secretString);
        console.log('Payload:', payload);
        console.log('SecretString:', secretString);

        const token = await createAndSignJWTWithSecret(payload, secret);
        console.log('Generated Token:', token);
        if (!token) {
            throw new Error('Failed to create and sign JWT');
        }

        const encryptedToken = await symmetricEncryptJWT(token, secret);
        console.log('Encrypted Token:', encryptedToken);
        if (!encryptedToken) {
            throw new Error('Failed to encrypt JWT');
        }

        const client = axios.create({
            headers: {
                'Authorization': `Bearer ${encryptedToken}`
            }
        });

        console.log('Axios Client Created:', client);
        return client;
    } catch (error) {
        console.error('Error creating Axios client:', error);
        return undefined;
    }
}

module.exports = createSymmetricAxiosClient;
