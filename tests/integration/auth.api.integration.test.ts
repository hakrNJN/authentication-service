import express from 'express';
import 'reflect-metadata';
import request from 'supertest';

// Set up environment variables before any imports
process.env.USE_REDIS_BLACKLIST = 'false';
process.env.SHARED_SECRET = 'test-secret-key-for-integration-tests';
process.env.REDIS_URL = 'redis://fake:6379';
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error';
process.env.AWS_REGION = 'us-east-1';
process.env.COGNITO_USER_POOL_ID = 'us-east-1_testpool';
process.env.COGNITO_CLIENT_ID = 'testClientId123';
process.env.PORT = '3000';

// Mock Redis to prevent connection issues in tests
jest.mock('ioredis', () => {
  return jest.fn().mockImplementation(() => ({
    on: jest.fn(),
    setex: jest.fn().mockResolvedValue('OK'),
    get: jest.fn().mockResolvedValue(null),
    disconnect: jest.fn().mockResolvedValue(undefined),
  }));
});

// Create a mock auth adapter that will be used throughout the tests
const mockAuthAdapter = {
  authenticateUser: jest.fn(),
  respondToAuthChallenge: jest.fn(),
  refreshToken: jest.fn(),
  getUserFromToken: jest.fn(),
  signUp: jest.fn(),
  confirmSignUp: jest.fn(),
  signOut: jest.fn(),
  initiateForgotPassword: jest.fn(),
  confirmForgotPassword: jest.fn(),
  changePassword: jest.fn(),
  adminInitiateForgotPassword: jest.fn(),
  adminSetPassword: jest.fn(),
};

// Mock the entire Cognito adapter module to prevent real AWS calls
jest.mock('../../src/infrastructure/adapters/cognito/CognitoAuthAdapter', () => {
  return {
    CognitoAuthAdapter: jest.fn().mockImplementation(() => mockAuthAdapter)
  };
});

import { createApp } from '../../src/app';

describe('Auth Integration Tests', () => {
  let app: express.Application;

  beforeAll(async () => {
    app = createApp();
  });

  beforeEach(() => {
    // Reset all mocks before each test
    Object.values(mockAuthAdapter).forEach(mockFn => mockFn.mockClear());
  });

  afterAll(() => {
    // Clean up environment variables
    delete process.env.USE_REDIS_BLACKLIST;
    delete process.env.SHARED_SECRET;
    delete process.env.REDIS_URL;
    delete process.env.NODE_ENV;
    delete process.env.LOG_LEVEL;
    delete process.env.AWS_REGION;
    delete process.env.COGNITO_USER_POOL_ID;
    delete process.env.COGNITO_CLIENT_ID;
    delete process.env.PORT;
  });

  describe('System Endpoints', () => {
    it('should return 200 OK for GET /api/system/health', async () => {
      const response = await request(app).get('/api/system/health');
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('status', 'UP');
      expect(response.body).toHaveProperty('timestamp');
      expect(typeof response.body.timestamp).toBe('string');
    });

    it('should return server info for GET /api/system/server-info', async () => {
      const response = await request(app).get('/api/system/server-info');
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('nodeVersion');
      expect(response.body).toHaveProperty('environment', 'test');
      expect(response.body).toHaveProperty('os');
      expect(response.body.os).toHaveProperty('platform');
      expect(response.body.os).toHaveProperty('arch');
      expect(response.body.os).toHaveProperty('release');
      expect(response.body).toHaveProperty('timestamp');
    });

    it('should return metrics for GET /api/system/metrics', async () => {
      const response = await request(app).get('/api/system/metrics');
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('text/plain');
    });
  });

  describe('Auth Endpoints - Validation', () => {
    describe('POST /api/auth/signup', () => {
      it('should return 400 for missing required fields', async () => {
        const response = await request(app)
          .post('/api/auth/signup')
          .send({});

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('message');
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body).toHaveProperty('status', 'error');
      });

      it('should return 400 for invalid email format', async () => {
        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: 'testuser',
            password: 'TestPassword123!',
            attributes: {
              email: 'invalid-email',
              name: 'Test User'
            }
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('message');
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('email');
      });

      it('should return 400 for short password', async () => {
        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: 'testuser',
            password: '123',
            attributes: {
              email: 'test@example.com',
              name: 'Test User'
            }
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('message');
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('Password must be at least 8 characters');
      });
    });

    describe('POST /api/auth/login', () => {
      it('should return 400 for missing username', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            password: 'TestPassword123!'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('message');
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('Username is required');
      });

      it('should return 400 for missing password', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            username: 'testuser'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('message');
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('Password is required');
      });
    });

    describe('POST /api/auth/confirm-signup', () => {
      it('should return 400 for missing username', async () => {
        const response = await request(app)
          .post('/api/auth/confirm-signup')
          .send({
            confirmationCode: '123456'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('message');
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('Username is required');
      });
    });
  });

  describe('Auth Endpoints - Business Logic', () => {
    describe('POST /api/auth/signup', () => {
      it('should successfully register a new user', async () => {
        // Mock successful signup
        mockAuthAdapter.signUp.mockResolvedValue({
          userSub: 'test-user-id',
          userConfirmed: false,
          codeDeliveryDetails: {
            Destination: 'test@example.com',
            DeliveryMedium: 'EMAIL',
            AttributeName: 'email'
          }
        });

        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: 'testuser',
            password: 'TestPassword123!',
            attributes: {
              email: 'test@example.com',
              name: 'Test User'
            }
          });

        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('userSub', 'test-user-id');
        expect(response.body).toHaveProperty('userConfirmed', false);
        expect(response.body).toHaveProperty('codeDeliveryDetails');
        expect(mockAuthAdapter.signUp).toHaveBeenCalledWith({
          username: 'testuser',
          password: 'TestPassword123!',
          attributes: { email: 'test@example.com', name: 'Test User' }
        });
      });

      it('should handle signup errors from auth adapter', async () => {
        // Mock signup failure
        mockAuthAdapter.signUp.mockRejectedValue(new Error('Username already exists'));

        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: 'existinguser',
            password: 'TestPassword123!',
            attributes: {
              email: 'existing@example.com',
              name: 'Existing User'
            }
          });

        expect(response.status).toBe(500);
        expect(response.body).toHaveProperty('message');
        expect(mockAuthAdapter.signUp).toHaveBeenCalled();
      });
    });

    describe('POST /api/auth/confirm-signup', () => {
      it('should successfully confirm user signup', async () => {
        // Mock successful confirmation
        mockAuthAdapter.confirmSignUp.mockResolvedValue(undefined);

        const response = await request(app)
          .post('/api/auth/confirm-signup')
          .send({
            username: 'testuser',
            confirmationCode: '123456'
          });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('message');
        expect(mockAuthAdapter.confirmSignUp).toHaveBeenCalledWith('testuser', '123456');
      });

      it('should handle invalid confirmation code', async () => {
        // Mock confirmation failure
        mockAuthAdapter.confirmSignUp.mockRejectedValue(new Error('Invalid verification code'));

        const response = await request(app)
          .post('/api/auth/confirm-signup')
          .send({
            username: 'testuser',
            confirmationCode: 'invalid'
          });

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('message');
        expect(mockAuthAdapter.confirmSignUp).toHaveBeenCalled();
      });
    });

    describe('POST /api/auth/login', () => {
      it('should successfully login with valid credentials', async () => {
        // Mock successful login
        mockAuthAdapter.authenticateUser.mockResolvedValue({
          accessToken: 'mock-access-token',
          refreshToken: 'mock-refresh-token',
          idToken: 'mock-id-token',
          tokenType: 'Bearer',
          expiresIn: 3600
        });

        const response = await request(app)
          .post('/api/auth/login')
          .send({
            username: 'testuser',
            password: 'TestPassword123!'
          });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('accessToken', 'mock-access-token');
        expect(response.body).toHaveProperty('refreshToken', 'mock-refresh-token');
        expect(response.body).toHaveProperty('idToken', 'mock-id-token');
        expect(response.body).toHaveProperty('tokenType', 'Bearer');
        expect(response.body).toHaveProperty('expiresIn', 3600);
        expect(mockAuthAdapter.authenticateUser).toHaveBeenCalledWith('testuser', 'TestPassword123!');
      });

      it('should handle MFA challenge during login', async () => {
        // Import the MfaRequiredError for proper mocking
        const { MfaRequiredError } = require('../../src/domain/exceptions/AuthenticationError');
        const { ChallengeNameType } = require('@aws-sdk/client-cognito-identity-provider');

        // Mock MFA challenge by throwing MfaRequiredError
        mockAuthAdapter.authenticateUser.mockRejectedValue(
          new MfaRequiredError(
            'mock-session-token',
            ChallengeNameType.SOFTWARE_TOKEN_MFA,
            {},
            'Multi-Factor Authentication Required'
          )
        );

        const response = await request(app)
          .post('/api/auth/login')
          .send({
            username: 'testuser',
            password: 'TestPassword123!'
          });

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('name', 'MfaRequiredError');
        expect(response.body).toHaveProperty('session', 'mock-session-token');
        expect(response.body).toHaveProperty('challengeName', 'SOFTWARE_TOKEN_MFA');
        expect(mockAuthAdapter.authenticateUser).toHaveBeenCalled();
      });

      it('should handle invalid credentials', async () => {
        // Mock authentication failure
        mockAuthAdapter.authenticateUser.mockRejectedValue(new Error('Incorrect username or password'));

        const response = await request(app)
          .post('/api/auth/login')
          .send({
            username: 'testuser',
            password: 'wrongpassword'
          });

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('message');
        expect(mockAuthAdapter.authenticateUser).toHaveBeenCalled();
      });
    });

    describe('POST /api/auth/verify-mfa', () => {
      it('should successfully verify MFA and return tokens', async () => {
        // Mock successful MFA verification
        mockAuthAdapter.respondToAuthChallenge.mockResolvedValue({
          accessToken: 'mock-access-token-after-mfa',
          refreshToken: 'mock-refresh-token-after-mfa',
          idToken: 'mock-id-token-after-mfa',
          tokenType: 'Bearer',
          expiresIn: 3600
        });

        const response = await request(app)
          .post('/api/auth/verify-mfa')
          .send({
            username: 'testuser',
            session: 'mock-session-token-12345678901234567890',
            challengeName: 'SOFTWARE_TOKEN_MFA',
            code: '123456'
          });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('accessToken', 'mock-access-token-after-mfa');
        expect(response.body).toHaveProperty('refreshToken', 'mock-refresh-token-after-mfa');
        expect(response.body).toHaveProperty('idToken', 'mock-id-token-after-mfa');
        expect(mockAuthAdapter.respondToAuthChallenge).toHaveBeenCalled();
      });

      it('should handle invalid MFA code', async () => {
        // Mock MFA verification failure
        mockAuthAdapter.respondToAuthChallenge.mockRejectedValue(new Error('Invalid MFA code'));

        const response = await request(app)
          .post('/api/auth/verify-mfa')
          .send({
            username: 'testuser',
            session: 'mock-session-token-12345678901234567890',
            challengeName: 'SOFTWARE_TOKEN_MFA',
            code: 'invalid'
          }
          ); // Removed extra closing brace here

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('message');
        expect(mockAuthAdapter.respondToAuthChallenge).toHaveBeenCalled();
      });
    });

    describe('POST /api/auth/refresh-token', () => {
      it('should successfully refresh tokens', async () => {
        // Mock successful token refresh
        mockAuthAdapter.refreshToken.mockResolvedValue({
          accessToken: 'new-mock-access-token',
          idToken: 'new-mock-id-token',
          tokenType: 'Bearer',
          expiresIn: 3600
        });

        const response = await request(app)
          .post('/api/auth/refresh-token')
          .send({
            refreshToken: 'mock-refresh-token'
          }
          ); // Removed extra closing brace here

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('accessToken', 'new-mock-access-token');
        expect(response.body).toHaveProperty('idToken', 'new-mock-id-token');
        expect(mockAuthAdapter.refreshToken).toHaveBeenCalledWith('mock-refresh-token');
      });

      it('should handle invalid refresh token', async () => {
        // Mock refresh token failure
        mockAuthAdapter.refreshToken.mockRejectedValue(new Error('Invalid refresh token'));

        const response = await request(app)
          .post('/api/auth/refresh-token')
          .send({
            refreshToken: 'invalid-refresh-token'
          }
          ); // Removed extra closing brace here

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('message');
        expect(mockAuthAdapter.refreshToken).toHaveBeenCalled();
      });
    });

    describe('POST /api/auth/forgot-password', () => {
      it('should successfully initiate forgot password flow', async () => {
        // Mock successful forgot password initiation
        mockAuthAdapter.initiateForgotPassword.mockResolvedValue({
          Destination: 't***@e*****.com',
          DeliveryMedium: 'EMAIL',
          AttributeName: 'email'
        });

        const response = await request(app)
          .post('/api/auth/forgot-password')
          .send({
            username: 'testuser@example.com'
          });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('message');
        expect(response.body.message).toBe('If a matching account was found, a password reset code has been sent.');
        expect(mockAuthAdapter.initiateForgotPassword).toHaveBeenCalledWith('testuser@example.com');
      });

      it('should handle user not found with same response (prevent enumeration)', async () => {
        // Mock user not found, but still return same shape of response
        mockAuthAdapter.initiateForgotPassword.mockResolvedValue({
          Destination: 'm***@e*****.com',
          DeliveryMedium: 'EMAIL',
          AttributeName: 'email'
        });

        const response = await request(app)
          .post('/api/auth/forgot-password')
          .send({
            username: 'nonexistent@example.com'
          });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('message');
        expect(response.body.message).toBe('If a matching account was found, a password reset code has been sent.');
        expect(mockAuthAdapter.initiateForgotPassword).toHaveBeenCalledWith('nonexistent@example.com');
      });

      it('should handle invalid email format', async () => {
        const response = await request(app)
          .post('/api/auth/forgot-password')
          .send({
            username: 'not-an-email'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('Invalid email format');
      });

      it('should handle rate limiting errors', async () => {
        // Mock a rate limit exceeded error
        mockAuthAdapter.initiateForgotPassword.mockRejectedValue(
          new Error('LimitExceededException: Attempt limit exceeded, please try after some time.')
        );

        const response = await request(app)
          .post('/api/auth/forgot-password')
          .send({
            username: 'testuser@example.com'
          });

        // Should still return 200 for security, but with same generic message
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('message');
        expect(response.body.message).toBe('If a matching account was found, a password reset code has been sent.');
      });
    });
  });

  describe('Protected Endpoints', () => {
    describe('GET /api/auth/me', () => {
      it('should return 401 for missing authorization header', async () => {
        const response = await request(app).get('/api/auth/me');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('message');
      });

      it('should return 401 for invalid token format', async () => {
        const response = await request(app)
          .get('/api/auth/me')
          .set('Authorization', 'InvalidToken');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('message');
      });

      // Note: Testing valid token scenarios would require mocking the auth guard middleware
      // which is more complex and might be better suited for unit tests
    });

    describe('POST /api/auth/logout', () => {
      it('should return 401 for missing authorization header', async () => {
        const response = await request(app).post('/api/auth/logout');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('message');
      });
    });

    describe('POST /api/auth/change-password', () => {
      it('should return 401 for missing authorization header', async () => {
        const response = await request(app)
          .post('/api/auth/change-password')
          .send({
            previousPassword: 'oldpass',
            proposedPassword: 'newpass123!'
          });

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('message');
      });
    });
  });
});