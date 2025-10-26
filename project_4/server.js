const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve your HTML file

// In-memory storage (replace with database in production)
let users = [];
let exams = [];

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, email, password, institutionName, institutionType, studentCount, country, algorithm } = req.body;

    // Check if user exists
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = {
      id: users.length + 1,
      fullName,
      email,
      password: hashedPassword,
      institutionName,
      institutionType,
      studentCount,
      country,
      algorithm,
      createdAt: new Date()
    };

    users.push(user);

    // Generate token
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { ...user, password: undefined }
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);

    res.json({
      message: 'Login successful',
      token,
      user: { ...user, password: undefined }
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected routes
app.get('/api/dashboard', authenticateToken, (req, res) => {
  const userExams = exams.filter(exam => exam.userId === req.user.userId);
  res.json({ exams: userExams });
});

app.post('/api/exams', authenticateToken, (req, res) => {
  const exam = {
    id: exams.length + 1,
    userId: req.user.userId,
    ...req.body,
    createdAt: new Date()
  };
  exams.push(exam);
  res.status(201).json(exam);
});

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});