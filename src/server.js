const time = require('./utils/timeUtils');

const authRoutes = require('./routers/authRoutes');
const paymentRoutes = require('./routers/paymentRoutes');
const generalRoutes = require('./routers/generalRoutes');

const express = require('express');
const bodyParser = require('body-parser');

require('dotenv').config();

const app = express();
const port = process.env.PORT || 1000;

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }

    next();
});

app.use(express.json());
// app.use(bodyParser.json());
// app.use(bodyParser.text());

app.use('/api', generalRoutes);
app.use('/api', authRoutes);
app.use('/api/payment', paymentRoutes);

app.listen(port, () => 
{
    console.log(`[${time.getCurrentTimestamp()}] ` +
    `Unigram Payment API running at ${process.env.SERVER_DOMAIN}, with port: ${port}`);
});
