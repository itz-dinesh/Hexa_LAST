const express = require('express');
const mysql = require('mysql');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(cors({
  origin: 'http://localhost:5173', // Ensure this matches your frontend URL
  credentials: true,
}));

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// MySQL database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
  } else {
    console.log('Connected to the MySQL database');
  }
});

// Signup route
app.post('/api/signup', (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const checkQuery = 'SELECT * FROM users WHERE email = ?';
  db.query(checkQuery, [email], (err, result) => {
    if (err) {
      console.error('Error checking user:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (result.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const query = 'INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)';
    db.query(query, [firstName, lastName, email, password], (error) => {
      if (error) {
        console.error('Error inserting user:', error);
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(201).json({ message: 'User created successfully' });
    });
  });
});

// Google login route
app.post('/api/google-login', async (req, res) => {
  const { token } = req.body;

  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const { email_verified, email, name } = ticket.getPayload();

    if (email_verified) {
      const checkQuery = 'SELECT * FROM users WHERE email = ?';
      db.query(checkQuery, [email], (err, result) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }

        if (result.length > 0) {
          return res.status(200).json({ message: 'Login successful', user: result[0] });
        } else {
          const insertQuery = 'INSERT INTO users (email, first_name) VALUES (?, ?)';
          db.query(insertQuery, [email, name], (err) => {
            if (err) {
              return res.status(500).json({ error: 'Database error' });
            }
            return res.status(201).json({ message: 'User created successfully' });
          });
        }
      });
    } else {
      return res.status(400).json({ error: 'Email not verified' });
    }
  } catch (error) {
    console.error('Error during Google login:', error);
    return res.status(500).json({ error: 'Authentication error' });
  }
});

// Update Profile route
app.post('/api/updateProfile', (req, res) => {
  const { firstName, lastName, degree, specialization, phone, email, linkedIn, gitHub, languages, certifications } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required to update the profile' });
  }

  const sql = `
    INSERT INTO user_profiles (first_name, last_name, degree, specialization, phone, email, linkedIn, gitHub, languages, certifications)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      first_name = VALUES(first_name),
      last_name = VALUES(last_name),
      degree = VALUES(degree),
      specialization = VALUES(specialization),
      phone = VALUES(phone),
      linkedIn = VALUES(linkedIn),
      gitHub = VALUES(gitHub),
      languages = VALUES(languages),
      certifications = VALUES(certifications);
  `;

  db.query(sql, [
    firstName,
    lastName,
    degree,
    specialization,
    phone,
    email,
    linkedIn,
    gitHub,
    JSON.stringify(languages),
    JSON.stringify(certifications)
  ], (err) => {
    if (err) {
      console.error('Error updating profile:', err);
      return res.status(500).send({ error: 'Failed to update profile', details: err });
    }
    console.log('Profile updated successfully');
    res.send('Profile updated successfully');
  });
});

// Login route
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const query = 'SELECT * FROM users WHERE email = ? AND password = ?';
  db.query(query, [email, password], (error, results) => {
    if (error) {
      console.error('Database error during login:', error);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.status(200).json({ message: 'Login successful' });
  });
});

// Fetch watched videos for a specific user
app.get('/api/watched-videos', (req, res) => {
  const userId = req.query.userId; // Assuming userId is sent in query params

  const query = 'SELECT video_title FROM video_progress WHERE user_id = ? AND is_completed = true';

  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).send('Error fetching watched videos');
    }
    const watchedVideos = results.map(row => row.video_title);
    res.json(watchedVideos);
  });
});

// Mark video as watched
app.post('/api/mark-watched', (req, res) => {
  const { userId, videoTitle } = req.body;

  const query = `
    INSERT INTO video_progress (user_id, video_title, is_completed)
    VALUES (?, ?, true)
    ON DUPLICATE KEY UPDATE is_completed = true;
  `;

  db.query(query, [userId, videoTitle], (err) => {
    if (err) {
      return res.status(500).send('Error marking video as watched');
    }
    res.sendStatus(200);
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
