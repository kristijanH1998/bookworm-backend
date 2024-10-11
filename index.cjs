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

// app.get('/cars', async function(req, res) {
//   try {
//     const [cars] = await req.db.query(`SELECT * FROM car WHERE deleted_flag=0`);
//     // console.log('/test endpoint reached');
//     // console.log(cars)
//     res.json(cars);
//   } catch (err) {
//     res.json({ success: false, message: err, data: null })
//   }
// });

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

    // console.log('jwtEncodedUser', jwtEncodedUser);

    res.status(200).json({ jwt: jwtEncodedUser, success: true });
  } catch (err) {
    // console.log('error', err);
    res.status(400).json({ error: 'Registration failed. Please try again.', success: false });
  }
});

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
    // console.log('Error in /authenticate', err);
    res.status(400).json({ err, success: false });
  }
});


// Jwt verification checks to see if there is an authorization header with a valid jwt in it.
// To hit any of the endpoints below this function, all requests have to first pass this verification 
// middleware function before they can be processed successfully and return a response
app.use(async function verifyJwt(req, res, next) {
  // console.log(req.headers)
  const { authorization: authHeader } = req.headers;
  
  if (!authHeader) res.json('Invalid authorization, no authorization headers');
  
  const [scheme, jwtToken] = authHeader.split(' ');

  if (scheme !== 'Bearer') res.json('Invalid authorization, invalid authorization scheme');

  try {
    const decodedJwtObject = jwt.verify(jwtToken, process.env.JWT_KEY);

    req.user = decodedJwtObject;
    // console.log(jwtToken)
    // console.log(decodedJwtObject)
    // console.log(jwt.verify(jwtToken, process.env.JWT_KEY)["email"]);
  } catch (err) {
    // console.log(err);
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

app.get('/log-out', async function (req, res) {
  try {
    res.status(200).json({ message: "Successfully signed out.", success: true });
  } catch (err) {
    res.status(400).json({ err, success: false });
  }
});

// app.post('/car', async function(req, res) {
//   try {
//     const { make, model, year } = req.body;
  
//     const query = await req.db.query(
//       `INSERT INTO car (make, model, year) 
//        VALUES (:make, :model, :year)`,
//       {
//         make,
//         model,
//         year,
//       }
//     );
  
//     res.json({ success: true, message: 'Car successfully created', data: null });
//   } catch (err) {
//     res.json({ success: false, message: err, data: null })
//   }
// });

// app.delete('/car/:id', async function(req,res) {
//   try {
//     console.log('req.params /car/:id', req.params)
//     const { id } = req.params;
//     await req.db.query(
//       `UPDATE car SET deleted_flag = 1 WHERE id = :id`,
//       { id }
//     );
//     res.json({ success: true, message: 'Car successfully deleted', data: null })
//   } catch (err) {
//     res.json({ success: false, message: err, data: null })
//   }
// });

// app.put('/car', async function(req,res) {
//   try {
//     const {id, make, model, year} = req.body;
//     const [cars] = await req.db.query(
//       `UPDATE car SET make = :make, model = :model, year = :year WHERE id = :id`,
//       {id, make, model, year}
//     );
//     res.json({ id, make, model, year, success: true });
//   } catch (err) {
//     res.json({ success: false, message: err, data: null })
//   }
// });

const apiKey = process.env.API_KEY;

app.get('/search-books', async function (req, res) {
  try {
    const searchParams = req.query;
    // console.log(searchParams)
    // console.log(searchParams['search-terms'])
    let response;
    // formatting the request body content by replacing whitespaces with '+' symbols to make it compatible
    // with the URL syntax
    searchParams['search-terms'] = searchParams['search-terms'].replace(/ /g, '+');
    // console.log(`https://www.googleapis.com/books/v1/volumes?q=in${searchParams['criteria']}:` + 
    //     `${searchParams['search-terms']}&printType=books&filter=full&fields=items/id,items/volumeInfo` + 
    //     `(title,authors,industryIdentifiers,categories,publisher,publishedDate,` + 
    //     `description,imageLinks,pageCount,language)`);
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
    // console.log(JSON.stringify(data, null, 2))
    res.status(200).json({ message: "Search successful.", success: true, data: data });
  } catch (err) {
    res.status(400).json({ err, success: false });
  }
});

app.post('/add-to-list', async function(req, res) {
  try {
    const { title, author, publisher, year, identifier, thumbnail, table} = req.body.data;
    //two lines below take the JWT token from request authorization header, and then extract user email from the JWT
    const jwtToken = req.headers.authorization.split(' ')[1];
    const user = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    // console.log(title, author, publisher, year, identifier, thumbnail, table);
    //console.log(table);
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

app.get('/fav-books', async function(req, res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const [favorites] = await req.db.query(`SELECT * FROM favorite WHERE user=:userEmail`, {userEmail});
    // console.log(favorites)
    res.json({ success: true, message: 'Favorites successfully returned', data: favorites });
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

app.get('/finished-books', async function(req, res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const [finishedBooks] = await req.db.query(`SELECT * FROM finished_reading WHERE user=:userEmail`, {userEmail});
    // console.log(finishedBooks)
    res.json({ success: true, message: 'Previously read books successfully returned', data: finishedBooks });
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

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

app.get('/user-data', async function(req, res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const [user] = await req.db.query(`SELECT email, user_name, first_name, last_name, date_of_birth 
      FROM user WHERE email=:userEmail FETCH FIRST 1 ROWS ONLY`, {userEmail});
    console.log(user)
    res.json({success: true, message: 'User data successully returned', data: user});
  } catch (err) {
    res.json({ success: false, message: err, data: null })
  }
});

app.delete('/delete', async function(req,res) {
  try {
    const jwtToken = req.headers.authorization.split(' ')[1];
    const userEmail = jwt.verify(jwtToken, process.env.JWT_KEY)["email"];
    const { identifier, table } = req.query;
    // console.log(identifier, table, userEmail);
    // console.log(req.params);
    const query = await req.db.query(
      `DELETE FROM ` + table + ` WHERE identifier = :identifier AND user = :userEmail`,
      { identifier, userEmail }
    );
    res.json({ success: true, message: 'Book successfully deleted', data: null });
  } catch (err) {
    res.json({ success: false, message: err, data: null });
  }
});

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

app.listen(port, () => console.log(`212 API Example listening on http://localhost:${port}`));