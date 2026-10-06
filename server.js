require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());

app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: 'Too many login attempts from this IP. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

let MOCK_DB_USER = null;

(async () => {
  const mockPassword = "SecurePassword123!";
  const hash = await argon2.hash(mockPassword, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16,
    timeCost: 3,
    parallelism: 1
  });
  
  MOCK_DB_USER = {
    id: "usr_991674354",
    email: "keshavsriramk@gmail.com",
    passwordHash: hash
  };
})();

app.post('/api/v1/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    if (!MOCK_DB_USER || email.toLowerCase() !== MOCK_DB_USER.email) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const isPasswordValid = await argon2.verify(MOCK_DB_USER.passwordHash, password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const token = jwt.sign(
      { userId: MOCK_DB_USER.id, email: MOCK_DB_USER.email },
      process.env.JWT_SECRET || 'super_secret_jwt_key_change_in_production',
      { expiresIn: '15m' }
    );

    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });

    return res.status(200).json({
      status: 'success',
      message: 'Authentication successful.',
      user: { id: MOCK_DB_USER.id, email: MOCK_DB_USER.email }
    });

  } catch (error) {
    console.error('Auth Error:', error);
    return res.status(500).json({ message: 'An unexpected error occurred.' });
  }
});

app.listen(PORT, () => {
  console.log(`[AUTH-SERVICE] Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});