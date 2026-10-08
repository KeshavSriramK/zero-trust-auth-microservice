const request = require('supertest');
const app = require('./server');
const db = require('./db');

const TEST_EMAIL = `test_${Date.now()}@example.com`;
const TEST_PASSWORD = 'SecurePassword123!';

afterAll(async () => {
  // Clean up test user from Neon database
  await db.query('DELETE FROM users WHERE email = $1', [TEST_EMAIL]);
  // Close pool connection so Jest exits cleanly
  await db.pool.end();
});

describe('Authentication API Integration Tests', () => {

  it('1. Should register a new user successfully', async () => {
    const res = await request(app)
      .post('/api/register')
      .send({
        email: TEST_EMAIL,
        password: TEST_PASSWORD
      });

    expect(res.statusCode).toEqual(201);
    expect(res.body).toHaveProperty('message', 'Account created successfully.');
    expect(res.body.user).toHaveProperty('id');
    expect(res.body.user.email).toEqual(TEST_EMAIL);
  });

  it('2. Should reject registration with duplicate email', async () => {
    const res = await request(app)
      .post('/api/register')
      .send({
        email: TEST_EMAIL,
        password: TEST_PASSWORD
      });

    expect(res.statusCode).toEqual(409);
    expect(res.body).toHaveProperty('error', 'Email address is already registered.');
  });

  it('3. Should authenticate user and return secure HTTP-only cookies', async () => {
    const res = await request(app)
      .post('/api/login')
      .send({
        email: TEST_EMAIL,
        password: TEST_PASSWORD
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty('message', 'Login successful.');

    // Verify set-cookie header contains access_token and refresh_token
    const cookies = res.headers['set-cookie'].join(';');
    expect(cookies).toContain('access_token');
    expect(cookies).toContain('refresh_token');
  });

  it('4. Should reject login with incorrect password', async () => {
    const res = await request(app)
      .post('/api/login')
      .send({
        email: TEST_EMAIL,
        password: 'WrongPassword999!'
      });

    expect(res.statusCode).toEqual(401);
    expect(res.body).toHaveProperty('error', 'Invalid email or password.');
  });

});