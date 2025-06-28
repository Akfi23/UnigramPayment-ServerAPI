const crypto = require('crypto-js');
const jwt = require ('jsonwebtoken');

require('dotenv').config();

function generateClientId(secret) {
    return crypto.createHash('sha256').update(secret).digest('hex');
}

function startClientCheckIn(request, result)
{
    const { secretKey } = request.body;

    if (!secretKey || secretKey !== process.env.CLIENT_SECRET_KEY) {
        return response.status(401).json({ error: 'Unauthorized client, access denied.' });
    }

    const clientId = generateClientId(secretKey);

    const token = jwt.sign({ clientId }, process.env.CLIENT_JWT_SIGN, { expiresIn: '1h' });

    response.json({ token });
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
