// asymmetricMiddleware.js
const { verifyJWTWithRSA, decryptJWT } = require('./jwtUtils');

function asymmetricJWTMiddleware(signingPublicKey, encryptionPrivateKey) {
    return async (req, res, next) => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'No token provided' });
            }

            let token = authHeader.split(' ')[1];
            let payload;

            if (encryptionPrivateKey) {
                token = await decryptJWT(token, encryptionPrivateKey);
            }
            payload = await verifyJWTWithRSA(token, signingPublicKey);
            req.jwtPayload = payload;
            next();
        } catch (err) {
            res.status(401).json({ error: 'Invalid token' });
        }
    };
}

module.exports = asymmetricJWTMiddleware;
