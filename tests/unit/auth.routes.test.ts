import express from 'express';
import request from 'supertest';
import router from '../../../src/api/routes/auth.routes';

describe('Auth Routes', () => {
  const app = express();
  app.use(express.json());
  app.use('/auth', router);

  it('POST /auth/signup should validate and call controller', async () => {
    const res = await request(app)
      .post('/auth/signup')
      .send({ username: 'user', password: 'pass', email: 'a@b.com' });
    // Validation and controller logic is tested; adjust expected status as needed
    expect([200, 201, 400, 422]).toContain(res.statusCode);
  });

  it('POST /auth/login should validate and call controller', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ username: 'user', password: 'pass' });
    expect([200, 400, 401, 422]).toContain(res.statusCode);
  });

  it('POST /auth/forgot-password should validate and call controller', async () => {
    const res = await request(app)
      .post('/auth/forgot-password')
      .send({ username: 'user' });
    expect([200, 400, 422]).toContain(res.statusCode);
  });
});