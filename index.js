const express = require('express');
const app = express();
const port = 5000;

const bcrypt = require('bcrypt');
const saltRounds = 10;

const sqlite3 = require('sqlite3').verbose();

const jwt = require('jsonwebtoken');

const db = new sqlite3.Database('./database/database.sqlite3', (err) => {
  if (err) {
    return console.error(err.message);
  }
  console.log('Connected to the SQlite database.');
});

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Good morning!');
});

app.get('/api/users', (req, res, next) => {
  const sql = "select * from users";
  const params = [];
  db.all(sql, params, (err,  rows) => {
    if (err) {
      return res.status(400).json({"error":err.message});
    }
    return res.json({
      "message":"success",
      "data": rows
    })
  })
})

app.post('/api/auth/register/', (req, res) => {
  const insert = 'INSERT INTO USERS (name, email, password) VALUES (?, ?, ?)'
  bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
    db.run(insert, [req.body.name,req.body.email,hash],(err) => {
      if (err) {
        return res.status(400).json({"error":err.message});
      }
      return res.json({
        "message": "create User successfully",
        "data": [req.body.name, req.body.email]
      })
    })
  })
})

app.post('/api/auth/login/',(req,res) => {
  const sql = 'select * from users where email = ?'
  const params = [req.body.email]
  db.get(sql, params, (err, user) => {
    if (err) {
      return res.status(400).json({"error":err.message});
    }
    if(!user){
      return res.json({"message": "email not found"})
    }
    bcrypt.compare(req.body.password, user.password, (err,result) => {
      if (err) {
        return res.status(400).json({"error":err.message});
      }
      if (!result) {
        return res.json({"message" : "password is not correct"})
      }
      const payload = {
        id: user.id,
        name: user.name,
        email: user.email
      }

      const token = jwt.sign(payload,'secret');
      return res.json({token});
    })
  })
})

app.get('/api/auth/user/',(req,res) => {

  const bearToken = req.headers['authorization']
  const bearer = bearToken.split(' ')
  const token = bearer[1]

  jwt.verify(token,'secret',(err,user)=>{
    if(err){
      return res.sendStatus(403)
    }else{
      return res.json({
            user
          });
    }
  })
});


app.listen(port, () => console.log(`Example app listening on port ${port}!`));


