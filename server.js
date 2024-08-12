// server.js
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// In-memory storage for demo purposes. Replace with a real database.
const users = [
  { id: 1, username: 'john', password: 'hashed_password' },
  { id: 2, username: 'jane', password: 'hashed_password' },
];

app.use(express.json());

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = users.find((user) => user.username === username);

  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const isValidPassword = bcrypt.compareSync(password, user.password);

  if (!isValidPassword) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = jwt.sign({ userId: user.id }, process.env.SECRET_KEY, {
    expiresIn: '1h',
  });

  res.json({ token });
});

// Protected endpoint
app.get('/dashboard', authenticate, (req, res) => {
  res.json({ message: 'Welcome to the dashboard!' });
});

// Authentication middleware
function authenticate(req, res, next) {
  const token = req.headers['x-access-token'] || req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.userId = decoded.userId;
    next();
  });
}

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});