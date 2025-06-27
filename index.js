const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const { config } = require('dotenv');
const path = require('path');
const routes = require('./src/users.controller');

config();
const app = express();
const PORT = process.env.PORT;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/v1', routes);
mongoose.connect(process.env.DB_URL)
.then(() => {
    console.log('Database connected succesfully');
    app.listen(PORT, () => {
        console.log(`App running in port ${PORT}`);
    });
})
.catch(() => {
    console.log('Database connection failed');
});
