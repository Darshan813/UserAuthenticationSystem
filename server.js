const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');

const app = express();
const port = 3000;

// MySQL database connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Darshan12345',
  database: 'user'
});

// Connect to MySQL database
connection.connect((err) => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  console.log('Connected to MySQL database'); 
});

// Middleware to parse JSON
app.use(express.json());

// Custom password encryption function
const encryptPassword = (password, salt) => {
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return hash;
};

// Custom password verification function
const verifyPassword = (password, salt, hash) => {
  const newHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return newHash === hash;
};

// User registration endpoint
app.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Please provide username, email, and password' });
  }

  // Check if user already exists
  connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Generate random salt
    const salt = crypto.randomBytes(16).toString('hex');
    // Encrypt password
    const hashedPassword = encryptPassword(password, salt);

    // Insert new user into database
    connection.query('INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)', 
      [username, email, hashedPassword, salt], (err, results) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        res.status(201).json({ message: 'User registered successfully' });
      });
  });
});

// User login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Please provide email and password' });
  }

  // Find user by email
  connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = results[0];
    // Verify password
    if (!verifyPassword(password, user.salt, user.password)) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    res.json({ message: 'Login successful' });
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
