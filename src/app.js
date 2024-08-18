// app.js
const express = require('express');
const symmetricJWTMiddleware = require('./symmetricMiddleware');
const asymmetricJWTMiddleware = require('./asymmetricMiddleware');
const { generateRSAKeys, readKeys } = require('./jwtUtils');
const certPath = process.env.CERT_PATH;
const clientPublic = process.env.CLIENT_PUBLIC;
const serverPrivate = process.env.SERVER_PRIVATE;
const app = express();
const secret = 'your-256-bit-secret';

(async () => {
    const { publicKey, privateKey } = certPath ? await readKeys(certPath, null) : await generateRSAKeys();

    app.use('/symmetric', symmetricJWTMiddleware(secret));
    app.use('/asymmetric', asymmetricJWTMiddleware(publicKey, privateKey));

    app.get('/symmetric', (req, res) => {
        res.json({ message: 'Symmetric route', payload: req.jwtPayload });
    });

    app.get('/asymmetric', (req, res) => {
        res.json({ message: 'Asymmetric route', payload: req.jwtPayload });
    });

    if (require.main === module) {
        app.listen(3000, () => {
            console.log('Server running on port 3000');
        });
    }
})();

module.exports = app;
