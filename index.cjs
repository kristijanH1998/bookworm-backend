//storing required packages into constant variables which will be used throughout the program
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

//new Express application is saved locally in 'app' variable
const app = express();

require('dotenv').config();

//defining a port on which the web server will listen for incoming connections
const port = process.env.PORT;

//defining CORS options
const corsOptions = {
  origin: '*', 
  credentials: true,  
  'access-control-allow-credentials': true,
  optionSuccessStatus: 200,
}

//defining a pool for storing connections to the database
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

app.use(cors(corsOptions));
app.use(bodyParser.json());

//enabling named placeholders for SQL queries, and setting database values for SQL mode, time zone
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
// Endpoint for registering a new user account on BookWorm
// Hashes the password and inserts the info into the `user` table
app.post('/register', async function (req, res) {
  try {
    const { password, username, userIsAdmin, email, firstName, lastName, dateOfBirth } = req.body;
    const [[userEmail]] = await req.db.query(`SELECT email FROM user WHERE email = :email`, { email });
    if (userEmail) {
      return res.status(400).json({
        error: 'Email already in use.', success: false
      });
    }
    const [[userName]] = await req.db.query(`SELECT user_name FROM user WHERE user_name = :username`, { username });
    if (userName) {
      return res.status(400).json({
        error: 'Username already in use.', success: false
      });
    }
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
    res.status(200).json({ jwt: jwtEncodedUser, success: true });
  } catch (err) {
    res.status(400).json({ error: 'Registration failed. Please try again.', success: false });
  }
});

//Endpoint for logging into BookWorm as existing user
app.post('/log-in', async function (req, res) {
  try {
    const { email, password: userEnteredPassword } = req.body;
    const [[user]] = await req.db.query(`SELECT * FROM user WHERE email = :email`, { email });
    if (!user) {
      return res.status(400).json({
        error: 'Email not found', success: false
      });
    }
    const hashedPassword = `${user.password}`
    const passwordMatches = await bcrypt.compare(userEnteredPassword, hashedPassword);
    if (passwordMatches) {
      const payload = {
        userId: user.id,
        email: user.email,
        userIsAdmin: user.admin_flag
      }
      const jwtEncodedUser = jwt.sign(payload, process.env.JWT_KEY);
      res.status(200).json({ jwt: jwtEncodedUser, success: true });
    } else {
      res.status(400).json({ error: 'Password is wrong', success: false });
    }
  } catch (err) {
    res.status(400).json({ err, success: false });
  }
});

// Jwt verification checks to see if there is an authorization header with a valid jwt in it.
// To hit any of the endpoints below this function, all requests have to first pass this verification 
// middleware function before they can be processed successfully and return a response
// Below middleware function performs jwt verification for incoming requests from frontend
app.use(async function verifyJwt(req, res, next) {
  const { authorization: authHeader } = req.headers;
  if (!authHeader) res.json('Invalid authorization, no authorization headers');
  const [scheme, jwtToken] = authHeader.split(' ');
  if (scheme !== 'Bearer') res.json('Invalid authorization, invalid authorization scheme');
  try {
    const decodedJwtObject = jwt.verify(jwtToken, process.env.JWT_KEY);
    req.user = decodedJwtObject;
  } catch (err) {
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

// Endpoint for logging out of BookWorm
app.get('/log-out', async function (req, res) {
  try {
    res.status(200).json({ message: "Successfully signed out.", success: true });
  } catch (err) {
    res.status(400).json({ err, success: false });
  }
});

// Saving the Google Books API key into apiKey variable
const apiKey = process.env.API_KEY;

// Endpoint for searching books in Google Books database and fetching them back to BookWorm
app.get('/search-books', async function (req, res) {
  try {
    const searchParams = req.query;
    let response;
    // formatting the request body content by replacing whitespaces with '+' symbols to make it compatible
    // with the URL syntax
    searchParams['search-terms'] = searchParams['search-terms'].replace(/ /g, '+');
    if(searchParams['criteria'] === 'author' || searchParams['criteria'] === 'title') {
      response = await fetch(`https://www.googleapis.com/books/v1/volumes?q=in${searchParams['criteria']}:` + 
        `${searchParams['search-terms']}&printType=books&filter=full&fields=items/id,items/volumeInfo` + 
        `(title,authors,industryIdentifiers,categories,publisher,publishedDate,` + 
        `description,imageLinks,pageCount,language)&startIndex=${searchParams['page']}&key=${apiKey}`, {
        method: 'GET',
        headers: { 
          'Content-Type': 'application/json',
          'Accept-Encoding': 'gzip',
          'User-Agent': 'my program (gzip)'
        }
      }) 
    } else {
      response = await fetch(`https://www.googleapis.com/books/v1/volumes?q=isbn:` + 
        `${searchParams['search-terms']}&printType=books&filter=full&fields=items/id,items/volumeInfo` + 
        `(title,authors,industryIdentifiers,categories,publisher,publishedDate,` + 
        `description,imageLinks,pageCount,language)&startIndex=${searchParams['page']}&key=${apiKey}`, {
        method: 'GET',
        headers: { 
          'Content-Type': 'application/json',
          'Accept-Encoding': 'gzip',
          'User-Agent': 'my program (gzip)'
        }
      }) 
    }
    const data = await response.json();
    res.status(200).json({ message: "Search successful.", success: true, data: data });
  } catch (err) {
    res.status(400).json({ err, success: false });
  }
});

// Endpoint allowing the user to put selected books in appropriate category tables (favorites, wishlist, finished reading)
app.post('/add-to-list', async function(req, res) {
  try {
    const { title, author, publisher, year, identifier, thumbnail, table} = req.body.data;
    //two lines below take the JWT token from request authorization header, and then extract user email from the JWT
    const jwtToken = req.headers.authorization.split(' ')[1];
    const user = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    //name of the table into which the record will be inserted equals the string 'table' received from frontend
    const query = await req.db.query(
      `INSERT INTO ` + table + ` (title, author, publisher, year, identifier, thumbnail, user) 
       VALUES (:title, :author, :publisher, :year, :identifier, :thumbnail, :user)`,
      {
        title, author, publisher, year, identifier, thumbnail, user
      }
    );
    res.json({ success: true, message: 'Book successfully added to' + table, data: null });
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

// Endpoint for fetching favorite books from the database
app.get('/fav-books', async function(req, res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const [favorites] = await req.db.query(`SELECT * FROM favorite WHERE user=:userEmail`, {userEmail});
    res.json({ success: true, message: 'Favorites successfully returned', data: favorites });
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

// Endpoint for fetching books the user finished reading from the database
app.get('/finished-books', async function(req, res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const [finishedBooks] = await req.db.query(`SELECT * FROM finished_reading WHERE user=:userEmail`, {userEmail});
    res.json({ success: true, message: 'Previously read books successfully returned', data: finishedBooks });
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

// Endpoint for fetching wishlist books from the database
app.get('/wishlist', async function(req, res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const [wishlist] = await req.db.query(`SELECT * FROM wishlist WHERE user=:userEmail`, {userEmail});
    res.json({ success: true, message: 'List of books planned to read successfully returned', data: wishlist });
  } catch (err) {
    res.json({ success: false, message: err, data: null });
  }
});

// Endpoint for fetching user's account data
app.get('/user-data', async function(req, res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const [user] = await req.db.query(`SELECT email, user_name, first_name, last_name, date_of_birth 
      FROM user WHERE email=:userEmail FETCH FIRST 1 ROWS ONLY`, {userEmail});
    res.json({success: true, message: 'User data successully returned', data: user});
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

// Endpoint for deleting saved books from one of the three category tables (favorite, wishlist, finished reading)
app.delete('/delete', async function(req,res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const { identifier, table } = req.query;
    const query = await req.db.query(
      `DELETE FROM ` + table + ` WHERE identifier = :identifier AND user = :userEmail`,
      { identifier, userEmail }
    );
    res.json({ success: true, message: 'Book successfully deleted', data: null });
  } catch (err) {
    res.json({ success: false, message: err, data: null });
  }
});

// Endpoint for updating user account attributes
app.put('/update-user', async function(req,res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const {attribute, value} = req.body;
    const [userNew] = await req.db.query(
      `UPDATE user SET ${attribute} = :value WHERE email = :userEmail`,
      {value, userEmail}
    );
    res.json({ success: true, message: 'User updated sucessfully', data: userNew});
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

// Endpoint for updating user's current password with provided new password
app.put('/update-password', async function(req,res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const {oldPassword, newPassword} = req.body;
    const [[user]] = await req.db.query(`SELECT * FROM user WHERE email = :userEmail`, {userEmail});
    const hashedOldPassword = `${user.password}`
    const passwordMatches = await bcrypt.compare(oldPassword, hashedOldPassword);
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    if (passwordMatches) {
      const [passwordUpdated] = await req.db.query(
        `UPDATE user SET password = :hashedNewPassword WHERE email = :userEmail`,
        {hashedNewPassword, userEmail}
      );
      res.json({ success: true, message: 'Password updated sucessfully', data: passwordUpdated});
    } else {
      res.status(400).json({ error: 'Password is wrong', success: false });
    }
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

// Allowing the Express app to listen to requests coming to port specified in .env file
app.listen(port, () => console.log(`212 API Example listening on http://localhost:${port}`));