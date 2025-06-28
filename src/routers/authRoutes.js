const sessionValidation = require('../handlers/sessionValidation');
const express = require('express');
const router = express.Router();

router.use(express.json());

router.post('/authenticate', (request, result) => {
    sessionValidation.startClientCheckIn(request, result);
});

module.exports = router;
