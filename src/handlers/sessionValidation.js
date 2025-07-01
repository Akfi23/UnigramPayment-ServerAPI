const crypto = require('crypto-js');
const jwt = require ('jsonwebtoken');

require('dotenv').config();

function startClientCheckIn(request, result)
{
    const received = request.body.trim();
    const expected = process.env.CLIENT_SECRET_KEY;

    if (received === expected) {
        try {
            const token = jwt.sign(
                { clientId: 'unity-client' },
                process.env.CLIENT_JWT_SIGN,
                { expiresIn: '24h' }
            );

            console.log('JWT Сгенерирован:', token);
            return result.status(200).json({ token });

        } catch (err) {
            console.error('Ошибка генерации JWT:', err);
            return result.status(500).json({
                error: 'Internal Server Error',
                details: err.message
            });
        }
    }

    console.warn('Ключ не совпадает');
    return result.status(401).json({ error: 'Unauthorized client, access denied.' });
}

function authenticateClient(request, result, next)
{
    const authHeader = request.headers['authorization'];

    if (!authHeader)
    {
        return result.status(403).json(
        {
            error: 'Authorization token for client not detected, access denied.'
        });
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.CLIENT_JWT_SIGN, (error, decoded) => 
    {
        if (error)
        {
            return result.status(403).json({ error: 'Unauthorized client, access denied.'});
        }

        request.cliendId = decoded.clientId;

        next();
    });
}

function authenticateBot(request, result, next)
{
    const authHeader = request.headers['authorization'];

    if (!authHeader)
    {
        return result.status(403).json(
        {
            error: 'Authorization token for bot not detected, access denied.'
        });
    }

    const token = authHeader.split(' ')[1];
    const decryptedToken = crypto.AES.decrypt(token,
         process.env.BOT_SECRET_KEY).toString(crypto.enc.Utf8);

    if (decryptedToken !== process.env.BOT_TOKEN)
    {
        return result.status(403).json(
        {
            error: 'Unauthorized source request, access denied'
        });
    }

    next();
}

module.exports = 
{
    startClientCheckIn,

    authenticateBot,
    authenticateClient
};
