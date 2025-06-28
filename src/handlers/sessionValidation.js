const crypto = require('crypto-js');
const jwt = require ('jsonwebtoken');

require('dotenv').config();

function startClientCheckIn(request, result) {
    // Ожидаем, что тело запроса — JSON вида { secretKey: "test_unity_unigram" }
    const { secretKey } = request.body;

    // Проверяем, есть ли ключ и совпадает ли он с .env
    if (!secretKey || secretKey !== process.env.CLIENT_SECRET_KEY) {
        return result.status(401).json({
            error: 'Unauthorized client, access denied.'
        });
    }

    // Генерируем JWT токен
    const token = jwt.sign(
        { clientId: 'unity-client' },
        process.env.CLIENT_JWT_SIGN,
        { expiresIn: '24h' }
    );

    // Отправляем токен клиенту
    result.status(200).json({ token });
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
