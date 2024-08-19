const asymmetricJwtClient = require('./src/asymmetricJwtClient');
const asymmetricMiddleware = require('./src/asymmetricMiddleware');
const symmetricJwtClient = require('./src/symmetricJwtClient');
const symmetricMiddleware = require('./src/symmetricMiddleware');
const {
    createAndSignJWTWithRSA, 
    createAndSignJWTWithSecret,
    symmetricEncryptJWT,
    asymmetricEncryptJWT,
    decryptJWT,
    verifyJWTWithRSA,
    verifyJWTWithSecret
} = require('./src/jwtUtils');

module.exports = {
    symmetric: {
        sign: createAndSignJWTWithSecret,
        encrypt: symmetricEncryptJWT,
        decrypt: decryptJWT,
        verify: verifyJWTWithSecret,
        middleware: symmetricMiddleware,
        client: symmetricJwtClient 
    },
    asymmetric: {
        sign: createAndSignJWTWithRSA,
        encrypt: asymmetricEncryptJWT,
        decrypt: decryptJWT,
        verify: verifyJWTWithRSA,
        middleware: asymmetricMiddleware,
        client: asymmetricJwtClient
    }
};
