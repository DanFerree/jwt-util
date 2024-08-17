// symmetricMiddleware.js
const { verifyJWTWithSecret, decryptJWT } = require('./jwtUtils');

function symmetricJWTMiddleware(secret) {
    return async (req, res, next) => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'No token provided' });
            }

            const token = authHeader.split(' ')[1];
            let payload;

            try {
                payload = await verifyJWTWithSecret(token, secret);
            } catch (err) {
                // If verification fails, try decrypting and then verifying
                const decryptedToken = await decryptJWT(token, secret);
                payload = await verifyJWTWithSecret(decryptedToken, secret);
            }

            req.jwtPayload = payload;
            next();
        } catch (err) {
            res.status(401).json({ error: 'Invalid token' });
        }
    };
}

module.exports = symmetricJWTMiddleware;
