const express = require('express');
const app = express();

app.get('/', (req, res) => {
    res.send('Game Rewards Postback Server is Running Securely!');
});

app.get('/upwall-postback', (req, res) => {
    const subId = req.query.subId; 
    const reward = req.query.reward; 
    
    console.log(`Received Postback: User ${subId} earned ${reward} coins.`);

    if (!subId || !reward) {
        return res.status(400).send('Missing required parameters');
    }

    res.status(200).send('1');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
