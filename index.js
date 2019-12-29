const express = require('express');
const app = express();
const port = 5000;

const bcrypt = require('bcrypt');
const saltRounds = 10;

const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./database/database.sqlite3', (err) => {
  if (err) {
    return console.error(err.message);
  }
  console.log('Connected to the SQlite database.');
});



app.get('/', (req, res) => {
  res.send('Good morning!');
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));


