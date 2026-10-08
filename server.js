require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));

app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many authentication attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Helper: Generate Access and Refresh Tokens
const generateTokens = async (user) => {
  // Short-lived Access Token (15 mins)
  const accessToken = jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );

  // Opaque Refresh Token
  const rawRefreshToken = crypto.randomBytes(40).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawRefreshToken).digest('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  // Store hashed refresh token in database
  await db.query(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
    [user.id, tokenHash, expiresAt]
  );

  return { accessToken, rawRefreshToken };
};

// Middleware: Authenticate Access Token
const authenticateToken = (req, res, next) => {
  const token = req.cookies.access_token;

  if (!token) {
    return res.status(401).json({ error: 'Access token missing.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Access token expired or invalid.', code: 'TOKEN_EXPIRED' });
  }
};

// Middleware: Role-Based Access Control (RBAC)
const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: Insufficient privileges.' });
    }
    next();
  };
};

// ----------------------------------------------------
// ROUTES
// ----------------------------------------------------

// 1. User Registration
app.post('/api/register', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  try {
    const normalizedEmail = email.toLowerCase();
    const existingUser = await db.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [normalizedEmail]);

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Email address is already registered.' });
    }

    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1
    });

    const newUser = await db.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, role, created_at',
      [normalizedEmail, passwordHash]
    );

    res.status(201).json({ message: 'Account created successfully.', user: newUser.rows[0] });
  } catch (err) {
    console.error('Registration Error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 2. User Login
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const normalizedEmail = email.toLowerCase();
    const result = await db.query(
      'SELECT id, email, password_hash, role FROM users WHERE LOWER(email) = LOWER($1)',
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = result.rows[0];
    const isValid = await argon2.verify(user.password_hash, password);

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const { accessToken, rawRefreshToken } = await generateTokens(user);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000 // 15 mins
    });

    res.cookie('refresh_token', rawRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(200).json({
      message: 'Login successful.',
      user: { id: user.id, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 3. Token Rotation / Refresh Route
app.post('/api/refresh', async (req, res) => {
  const rawRefreshToken = req.cookies.refresh_token;

  if (!rawRefreshToken) {
    return res.status(401).json({ error: 'Refresh token missing.' });
  }

  try {
    const tokenHash = crypto.createHash('sha256').update(rawRefreshToken).digest('hex');

    // Find token record
    const result = await db.query(
      'SELECT id, user_id, expires_at FROM refresh_tokens WHERE token_hash = $1',
      [tokenHash]
    );

    if (result.rows.length === 0) {
      // Reuse detection: potential token reuse or theft
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      return res.status(403).json({ error: 'Invalid refresh token session. Please log in again.' });
    }

    const currentToken = result.rows[0];

    if (new Date() > new Date(currentToken.expires_at)) {
      await db.query('DELETE FROM refresh_tokens WHERE id = $1', [currentToken.id]);
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      return res.status(401).json({ error: 'Refresh token expired.' });
    }

    // Fetch user details
    const userResult = await db.query('SELECT id, email, role FROM users WHERE id = $1', [currentToken.user_id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User no longer exists.' });
    }
    const user = userResult.rows[0];

    // ROTATE TOKEN: Delete the consumed refresh token
    await db.query('DELETE FROM refresh_tokens WHERE id = $1', [currentToken.id]);

    // Issue new pair
    const { accessToken, rawRefreshToken: newRawRefreshToken } = await generateTokens(user);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });

    res.cookie('refresh_token', newRawRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(200).json({ message: 'Session refreshed successfully.' });
  } catch (err) {
    console.error('Refresh Error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 4. Protected User Profile Route
app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const result = await db.query('SELECT id, email, role, created_at FROM users WHERE id = $1', [req.user.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.status(200).json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 5. Admin-Only Protected Route
app.get('/api/admin', authenticateToken, authorizeRoles('admin'), (req, res) => {
  res.status(200).json({ message: 'Welcome to the Admin Dashboard.', user: req.user });
});

// 6. Logout / Revoke Session
app.post('/api/logout', async (req, res) => {
  const rawRefreshToken = req.cookies.refresh_token;

  if (rawRefreshToken) {
    const tokenHash = crypto.createHash('sha256').update(rawRefreshToken).digest('hex');
    await db.query('DELETE FROM refresh_tokens WHERE token_hash = $1', [tokenHash]);
  }

  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  res.status(200).json({ message: 'Logged out successfully.' });
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`Server running securely on http://localhost:${PORT}`);
  });
}

module.exports = app;