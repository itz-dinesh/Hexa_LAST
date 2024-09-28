const express = require('express');
const mysql = require('mysql');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const session = require('express-session'); // Import express-session

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(cors({
  origin: 'http://localhost:5173', // Ensure this matches your frontend URL
  credentials: true,
}));

// Configure session
app.use(session({
  secret: process.env.SESSION_SECRET || 'b224bf80e52ce64eb5d34f3acf0bbc16e9d2f94d365e715a61b14911d9c21469f66c655c9cda58e9b4ef04cb13d1f355ffb4c217e4311be20cc23f96ddcd79a1', // Set your session secret
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}));

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const JWT_SECRET = process.env.JWT_SECRET || 'b224bf80e52ce64eb5d34f3acf0bbc16e9d2f94d365e715a61b14911d9c21469f66c655c9cda58e9b4ef04cb13d1f355ffb4c217e4311be20cc23f96ddcd79a1'; // Set your JWT secret

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

// Function to generate a JWT token
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '24h' } // Token will expire in 24 hours
  );
}

// Middleware to verify token and maintain session
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Forbidden' });
    req.user = user; // Store the decoded user data
    next();
  });
}

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

    const query = 'INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)';
    db.query(query, [firstName, lastName, email, password], (error) => {
      if (error) {
        console.error('Error inserting user:', error);
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(201).json({ message: 'User created successfully' });
    });
  });
});

// Login route with JWT token generation
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

    const user = results[0];
    const token = generateToken(user);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now

    // Store session in the database
    const sessionQuery = 'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE token = ?, expires_at = ?';
    db.query(sessionQuery, [user.id, token, expiresAt, token, expiresAt], (err) => {
      if (err) {
        console.error('Error creating session:', err);
        return res.status(500).json({ error: 'Error creating session' });
      }

      // Send the token back to the client
      res.status(200).json({ message: 'Login successful', token });
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
          // User exists, generate a token
          const user = result[0];
          const jwtToken = generateToken(user);

          return res.status(200).json({ message: 'Login successful', token: jwtToken });
        } else {
          // Create a new user if not exists
          const insertQuery = 'INSERT INTO users (email, firstname) VALUES (?, ?)';
          db.query(insertQuery, [email, name], (err) => {
            if (err) {
              return res.status(500).json({ error: 'Database error' });
            }

            // Generate token for the newly created user
            const newUser = { id: result.insertId, email };
            const jwtToken = generateToken(newUser);

            return res.status(201).json({ message: 'User created successfully', token: jwtToken });
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
app.post('/api/updateProfile', authenticateToken, (req, res) => {
  const { firstName, lastName, degree, specialization, phone, email, linkedIn, gitHub, languages, certifications } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required to update the profile' });
  }

  const sql = `
    INSERT INTO user_profiles (firstname, lastname, degree, specialization, phone, email, linkedIn, gitHub, languages, certifications)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      firstname = VALUES(firstname),
      lastname = VALUES(lastname),
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

// Fetch watched videos for a specific user
app.get('/api/watched-videos', authenticateToken, (req, res) => {
  const userId = req.user.id; // Using the authenticated user from the token

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
app.post('/api/mark-watched', authenticateToken, (req, res) => {
  const { videoTitle } = req.body;
  const userId = req.user.id; // Using the authenticated user from the token

  const query = `
    INSERT INTO video_progress (user_id, video_title, is_completed)
    VALUES (?, ?, true)
    ON DUPLICATE KEY UPDATE is_completed = true;
  `;

  db.query(query, [userId, videoTitle], (err) => {
    if (err) {
      return res.status(500).send('Error marking video as watched');
    }
    res.send('Video marked as watched');
  });
});

// Logout route
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Could not log out');
    }
    res.send('Logged out successfully');
  });
});

// Server setup
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
