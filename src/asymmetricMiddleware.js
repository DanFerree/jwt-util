// asymmetricMiddleware.js
const { verifyJWTWithRSA, decryptJWT } = require('./jwtUtils');

function asymmetricJWTMiddleware(signingPublicKey, encryptionPrivateKey) {
    return async (req, res, next) => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'No token provided' });
            }

            const token = authHeader.split(' ')[1];
            let payload;

            try {
                payload = await verifyJWTWithRSA(token, signingPublicKey);
            } catch (err) {
                console.log('error validating asummetricJWT: ', err);
            }
            if(!payload){
                try {
                    // If verification fails, try decrypting and then verifying
                    const decryptedToken = await decryptJWT(token, encryptionPrivateKey);
                    payload = await verifyJWTWithRSA(decryptedToken, signingPublicKey);
                } catch (error) {
                    console.log('error decrypting asummetricJWT: ', error);  
                    throw new Error(error);
                }
            }
            req.jwtPayload = payload;
            next();
        } catch (err) {
            res.status(401).json({ error: 'Invalid token' });
        }
    };
}

module.exports = asymmetricJWTMiddleware;
