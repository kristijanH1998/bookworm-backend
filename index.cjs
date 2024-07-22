const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();

require('dotenv').config();

const port = process.env.PORT;

const corsOptions = {
  origin: '*', 
  credentials: true,  
  'access-control-allow-credentials': true,
  optionSuccessStatus: 200,
}

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

app.use(cors(corsOptions));

app.use(bodyParser.json());

// app.use(express.json());

app.use(async function(req, res, next) {
  try {
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;

    await req.db.query(`SET SESSION sql_mode = "TRADITIONAL"`);
    await req.db.query(`SET time_zone = '-8:00'`);

    await next();

    req.db.release();
  } catch (err) {
    console.log(err);

    if (req.db) req.db.release();
    throw err;
  }
});


// These endpoints can be reached without needing a JWT


app.get('/cars', async function(req, res) {
  try {
    const [cars] = await req.db.query(`SELECT * FROM car WHERE deleted_flag=0`);
    // console.log('/test endpoint reached');
    // console.log(cars)
    res.json(cars);
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

// app.use(async function(req, res, next) {
//   try {
//     console.log('Middleware after the get /cars');
  
//     await next();

//   } catch (err) {

//   }
// });



// Hashes the password and inserts the info into the `user` table
app.post('/register', async function (req, res) {
  try {
    const { password, username, userIsAdmin, email, firstName, lastName, dateOfBirth } = req.body;

    const isAdmin = userIsAdmin ? 1 : 0;

    const hashedPassword = await bcrypt.hash(password, 10);

    const [user] = await req.db.query(
      `INSERT INTO user (user_name, password, admin_flag, email, first_name, last_name, date_of_birth) 
      VALUES (:username, :hashedPassword, :userIsAdmin, :email, :firstName, :lastName, :dateOfBirth);`,
      { 
        username,
        hashedPassword,
        userIsAdmin: isAdmin,
        email, 
        firstName, 
        lastName, 
        dateOfBirth
      }
    );

    const jwtEncodedUser = jwt.sign(
      { userId: user.insertId, ...req.body, userIsAdmin: isAdmin },
      process.env.JWT_KEY
    );

    console.log('jwtEncodedUser', jwtEncodedUser);

    res.json({ jwt: jwtEncodedUser, success: true });
  } catch (err) {
    console.log('error', err);
    res.json({ err, success: false });
  }
});

app.post('/log-in', async function (req, res) {
  try {
    const { email, password: userEnteredPassword } = req.body;

    const [[user]] = await req.db.query(`SELECT * FROM user WHERE email = :email`, { email });

    if (!user) res.json('Email not found');
  
    const hashedPassword = `${user.password}`
    const passwordMatches = await bcrypt.compare(userEnteredPassword, hashedPassword);

    if (passwordMatches) {
      const payload = {
        userId: user.id,
        email: user.email,
        userIsAdmin: user.admin_flag
      }
      
      const jwtEncodedUser = jwt.sign(payload, process.env.JWT_KEY);

      res.json({ jwt: jwtEncodedUser, success: true });
    } else {
      res.json({ err: 'Password is wrong', success: false });
    }
  } catch (err) {
    console.log('Error in /authenticate', err);
  }
});








// Jwt verification checks to see if there is an authorization header with a valid jwt in it.
// To hit any of the endpoints below this function, all requests have to first pass this verification 
// middleware function before they can be processed successfully and return a response
app.use(async function verifyJwt(req, res, next) {
  const { authorization: authHeader } = req.headers;
  
  if (!authHeader) res.json('Invalid authorization, no authorization headers');
  
  const [scheme, jwtToken] = authHeader.split(' ');

  if (scheme !== 'Bearer') res.json('Invalid authorization, invalid authorization scheme');

  try {
    const decodedJwtObject = jwt.verify(jwtToken, process.env.JWT_KEY);

    req.user = decodedJwtObject;
  } catch (err) {
    console.log(err);
    if (
      err.message && 
      (err.message.toUpperCase() === 'INVALID TOKEN' || 
      err.message.toUpperCase() === 'JWT EXPIRED')
    ) {

      req.status = err.status || 500;
      req.body = err.message;
      req.app.emit('jwt-error', err, req);
    } else {

      throw((err.status || 500), err.message);
    }
  }

  await next();
});



app.post('/car', async function(req, res) {
  try {
    const { make, model, year } = req.body;
  
    const query = await req.db.query(
      `INSERT INTO car (make, model, year) 
       VALUES (:make, :model, :year)`,
      {
        make,
        model,
        year,
      }
    );
  
    res.json({ success: true, message: 'Car successfully created', data: null });
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

app.delete('/car/:id', async function(req,res) {
  try {
    console.log('req.params /car/:id', req.params)
    const { id } = req.params;
    await req.db.query(
      `UPDATE car SET deleted_flag = 1 WHERE id = :id`,
      { id }
    );

    res.json({ success: true, message: 'Car successfully deleted', data: null })
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

app.put('/car', async function(req,res) {
  try {
    const {id, make, model, year} = req.body;
    const [cars] = await req.db.query(
      `UPDATE car SET make = :make, model = :model, year = :year WHERE id = :id`,
      {id, make, model, year}
    );
    res.json({ id, make, model, year, success: true });
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});


app.listen(port, () => console.log(`212 API Example listening on http://localhost:${port}`));