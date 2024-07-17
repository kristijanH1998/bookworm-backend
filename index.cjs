const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();

require('dotenv').config();

const port = process.env.PORT;

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

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

app.use(cors());

app.use(express.json());

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

app.use(async function(req, res, next) {
  try {
    console.log('Middleware after the get /cars');
  
    await next();

  } catch (err) {

  }
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