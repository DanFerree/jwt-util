// symmetricMiddleware.js
const { verifyJWTWithSecret, decryptJWT } = require('./jwtUtils');

function symmetricJWTMiddleware(secret, encryption = false) {
    return async (req, res, next) => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'No token provided' });
            }

            let token = authHeader.split(' ')[1];
            let payload;

            if (encryption) {
                token = await decryptJWT(token, secret);
            }
            payload = await verifyJWTWithSecret(token, secret);

            req.jwtPayload = payload;
            next();
        } catch (err) {
            res.status(401).json({ error: 'Invalid token' });
        }
    };
}

module.exports = symmetricJWTMiddleware;
