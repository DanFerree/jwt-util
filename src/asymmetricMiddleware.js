// asymmetricMiddleware.js
const { verifyJWTWithRSA, decryptJWT } = require('./jwtUtils');

function asymmetricJWTMiddleware(publicKey, privateKey) {
    return async (req, res, next) => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'No token provided' });
            }

            const token = authHeader.split(' ')[1];
            let payload;

            try {
                payload = await verifyJWTWithRSA(token, publicKey);
            } catch (err) {
                // If verification fails, try decrypting and then verifying
                const decryptedToken = await decryptJWT(token, privateKey);
                payload = await verifyJWTWithRSA(decryptedToken, publicKey);
            }

            req.jwtPayload = payload;
            next();
        } catch (err) {
            res.status(401).json({ error: 'Invalid token' });
        }
    };
}

module.exports = asymmetricJWTMiddleware;
