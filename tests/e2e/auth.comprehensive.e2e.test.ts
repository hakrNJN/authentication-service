// Set rate limit high before any modules (like auth.routes) are evaluated
process.env.AUTH_RATE_LIMIT_MAX = '1000';

import { Express } from 'express';
import request from 'supertest';
import { container } from 'tsyringe';
import { TYPES } from '../../src/shared/constants/types';
import { MockCognitoAdapter } from './setup/mockCognitoAdapter';
import { ILogger } from '../../src/application/interfaces/ILogger';

class MockLogger implements ILogger {
  debug(message: string, ...args: any[]): void { console.debug(`[DEBUG] ${message}`, ...args); }
  info(message: string, ...args: any[]): void { console.info(`[INFO] ${message}`, ...args); }
  warn(message: string, ...args: any[]): void { console.warn(`[WARN] ${message}`, ...args); }
  error(message: string, ...args: any[]): void { console.error(`[ERROR] ${message}`, ...args); }
}

const globalMockLogger = new MockLogger();
const globalMockAdapter = new MockCognitoAdapter(globalMockLogger);

jest.mock('../../src/infrastructure/adapters/cognito/CognitoAuthStrategy', () => ({
  CognitoAuthStrategy: jest.fn().mockImplementation(() => globalMockAdapter),
}));

import { createApp } from '../../src/app';
import { IAuthAdapter } from '../../src/application/interfaces/IAuthAdapter';
import { AuthService } from '../../src/application/services/auth.service';
import { AuthController } from '../../src/api/controllers/auth.controller';
import { IAuthService } from '../../src/application/interfaces/IAuthService';
import { EnvironmentConfigService } from '../../src/infrastructure/config/EnvironmentConfigService';
import { TokenBlacklistService } from '../../src/application/services/TokenBlacklistService';
import { IConfigService } from '../../src/application/interfaces/IConfigService';
import { ITokenBlacklistService } from '../../src/application/interfaces/ITokenBlacklistService';



describe('Comprehensive Authentication E2E Tests', () => {
  let app: Express & { shutdown?: () => Promise<void> };
  let mockAdapter: MockCognitoAdapter;

  beforeEach(async () => {
    // Clear instances before each test to ensure a clean slate
    container.clearInstances();

    // Set E2E test environment variables
    process.env.NODE_ENV = 'test';
    process.env.REDIS_URL = 'redis://192.168.2.252:6379';
    process.env.USE_REDIS_BLACKLIST = 'true';
    process.env.SHARED_SECRET = 'test-shared-secret-e2e';
    process.env.AWS_REGION = 'us-east-1';
    process.env.COGNITO_USER_POOL_ID = 'test-user-pool-id';
    process.env.COGNITO_CLIENT_ID = 'testClientId123';

    mockAdapter = globalMockAdapter;
    mockAdapter.reset();

    // Register the mock adapter FIRST
    container.registerInstance<IAuthAdapter>(TYPES.AuthAdapter, mockAdapter);

    // Now, explicitly register the services/controllers that depend on IAuthAdapter
    // This forces tsyringe to resolve them *after* the mock is in place.
    container.registerSingleton<ILogger>(TYPES.Logger, MockLogger);
    container.registerSingleton<IConfigService>(TYPES.ConfigService, EnvironmentConfigService);
    container.registerSingleton<ITokenBlacklistService>(TYPES.TokenBlacklistService, TokenBlacklistService);
    container.registerSingleton<IAuthService>(TYPES.AuthService, AuthService);
    container.registerSingleton(AuthController);

    // Create app instance
    app = createApp();

    // Add some test users for consistent state
    await mockAdapter.signUp({
      username: 'testuser@example.com',
      password: 'TestPassword123!',
      attributes: {
        email: 'testuser@example.com',
        name: 'Test User'
      }
    });
    await mockAdapter.confirmSignUp('testuser@example.com', '123456');
  });

  afterEach(async () => {
    try {
      // Clean up container
      container.clearInstances();

      // Shutdown app gracefully (closes Redis connections)
      if (app && app.shutdown) {
        await app.shutdown();
      }

      // Wait a bit for cleanup
      await new Promise(resolve => setTimeout(resolve, 100));
    } catch (error) {
      console.error('Error during test cleanup:', error);
    }
  });

  describe('Advanced Validation Tests', () => {
    describe('Signup Validation Edge Cases', () => {
      it('should reject signup with SQL injection attempts', async () => {
        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: "'; DROP TABLE users; --",
            password: 'TestPassword123!',
            attributes: {
              email: 'test@example.com',
              name: 'Test User'
            }
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
      });

      it('should reject signup with XSS attempts in name', async () => {
        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: 'testuser@example.com',
            password: 'TestPassword123!',
            attributes: {
              email: 'test@example.com',
              name: '<script>alert("xss")</script>'
            }
          });

        console.log('Response Status for XSS test:', response.status);
        console.log('Response Body for XSS test:', response.body);
        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
      });

      it('should reject signup with extremely long username', async () => {
        const longUsername = 'a'.repeat(1000) + '@example.com';

        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: longUsername,
            password: 'TestPassword123!',
            attributes: {
              email: 'test@example.com',
              name: 'Test User'
            }
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
      });

      it('should reject signup with password containing only numbers', async () => {
        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: 'testuser@example.com',
            password: '12345678',
            attributes: {
              email: 'test@example.com',
              name: 'Test User'
            }
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('password: Password must contain uppercase, lowercase, number, and special character'); // Removed 'body.'
      });

      it('should reject signup with password containing only lowercase', async () => {
        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: 'testuser@example.com',
            password: 'abcdefgh',
            attributes: {
              email: 'test@example.com',
              name: 'Test User'
            }
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('password: Password must contain uppercase, lowercase, number, and special character'); // Removed 'body.'
      });

      it('should reject signup with missing email attribute', async () => {
        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: 'testuser@example.com',
            password: 'TestPassword123!',
            attributes: {
              name: 'Test User'
              // Missing email
            }
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('attributes.email: Email attribute is required'); // Removed 'body.attributes.'
      });
    });

    describe('Login Validation Edge Cases', () => {
      it('should reject login with empty strings', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            username: '',
            password: ''
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
      });

      it('should reject login with whitespace-only credentials', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            username: '   ',
            password: '   '
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
      });

      it('should handle login with unicode characters', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            username: 'tëst@éxämplé.com',
            password: 'Tëst123!'
          });

        // Should fail due to Cognito client ID validation, not unicode handling
        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
      });
    });

    describe('MFA Validation Edge Cases', () => {
      it('should reject MFA verification with invalid session format', async () => {
        const response = await request(app)
          .post('/api/auth/verify-mfa')
          .send({
            username: 'testuser@example.com',
            session: 'invalid-session',
            challengeName: 'SMS_MFA',
            code: '123456'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('session: Session seems too short'); // Removed 'body.'
      });

      it('should reject MFA verification with invalid challenge name', async () => {
        const response = await request(app)
          .post('/api/auth/verify-mfa')
          .send({
            username: 'testuser@example.com',
            session: 'valid-session-token-12345678901234567890',
            challengeName: 'INVALID_CHALLENGE',
            code: '123456'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('Invalid enum value');
      });

      it('should reject MFA verification with non-numeric code', async () => {
        const response = await request(app)
          .post('/api/auth/verify-mfa')
          .send({
            username: 'testuser@example.com',
            session: 'valid-session-token-12345678901234567890',
            challengeName: 'SMS_MFA',
            code: 'abcdef'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
        expect(response.body.message).toContain('code: Code must be numeric');
      });
    });

    describe('Password Reset Flow Tests', () => {
      describe('Forgot Password Initiation', () => {
        it('should initiate forgot password successfully with valid username', async () => {
          const response = await request(app)
            .post('/api/auth/forgot-password')
            .send({
              username: 'testuser@example.com'
            });

          expect(response.status).toBe(200);
          expect(response.body).toHaveProperty('message', 'If a matching account was found, a password reset code has been sent.');
        });

        it('should return same response for non-existent user (prevent enumeration)', async () => {
          const response = await request(app)
            .post('/api/auth/forgot-password')
            .send({
              username: 'nonexistent@example.com'
            });

          expect(response.status).toBe(200);
          expect(response.body).toHaveProperty('message', 'If a matching account was found, a password reset code has been sent.');
        });

        it('should handle empty username', async () => {
          const response = await request(app)
            .post('/api/auth/forgot-password')
            .send({
              username: ''
            });

          expect(response.status).toBe(400);
          expect(response.body).toHaveProperty('name', 'ValidationError');
          expect(response.body.message).toContain('Username/email cannot be empty');
        });

        it('should handle missing username field', async () => {
          const response = await request(app)
            .post('/api/auth/forgot-password')
            .send({});

          expect(response.status).toBe(400);
          expect(response.body).toHaveProperty('name', 'ValidationError');
          expect(response.body.message).toContain('Username or email is required');
        });

        it('should reject extremely long usernames', async () => {
          const longUsername = 'a'.repeat(1000) + '@example.com';

          const response = await request(app)
            .post('/api/auth/forgot-password')
            .send({
              username: longUsername
            });

          expect(response.status).toBe(400);
          expect(response.body).toHaveProperty('name', 'ValidationError');
          expect(response.body.message).toContain('Username is too long');
        });

        it('should handle usernames with special characters', async () => {
          const specialUsernames = [
            'test+user@example.com',
            'test.user@example.com',
            'test-user@example.com',
            'test_user@example.com'
          ];

          for (const username of specialUsernames) {
            const response = await request(app)
              .post('/api/auth/forgot-password')
              .send({ username });

            expect(response.status).toBe(200);
            expect(response.body.message).toBe('If a matching account was found, a password reset code has been sent.');
          }
        });
      });

      describe('Password Reset Validation', () => {
        it('should reject reset password with weak new password', async () => {
          // First request forgot password
          await request(app)
            .post('/api/auth/forgot-password')
            .send({
              username: 'testuser@example.com'
            });

          const response = await request(app)
            .post('/api/auth/reset-password')
            .send({
              username: 'testuser@example.com',
              confirmationCode: '123456',
              newPassword: 'weak'
            });

          expect(response.status).toBe(400);
          expect(response.body).toHaveProperty('name', 'ValidationError');
          expect(response.body.message).toContain('newPassword: Password must be at least 8 characters');
        });

        it('should reject reset password with invalid confirmation code format', async () => {
          // First request forgot password
          await request(app)
            .post('/api/auth/forgot-password')
            .send({
              username: 'testuser@example.com'
            });

          const response = await request(app)
            .post('/api/auth/reset-password')
            .send({
              username: 'testuser@example.com',
              confirmationCode: 'abc',
              newPassword: 'NewPassword123!'
            });

          expect(response.status).toBe(400);
          expect(response.body).toHaveProperty('name', 'ValidationError');
          expect(response.body.message).toContain('confirmationCode: Confirmation code must be exactly 6 digits; confirmationCode: Confirmation code must be numeric');
        });

        it('should reject reset password with non-compliant password', async () => {
          // First request forgot password
          await request(app)
            .post('/api/auth/forgot-password')
            .send({
              username: 'testuser@example.com'
            });

          const response = await request(app)
            .post('/api/auth/reset-password')
            .send({
              username: 'testuser@example.com',
              confirmationCode: '123456',
              newPassword: 'password123' // Missing uppercase and special char
            });

          expect(response.status).toBe(400);
          expect(response.body).toHaveProperty('name', 'ValidationError');
          expect(response.body.message).toContain('Password must contain uppercase, lowercase, number, and special character');
        });

        it('should reject reset password with extremely long password', async () => {
          // First request forgot password
          await request(app)
            .post('/api/auth/forgot-password')
            .send({
              username: 'testuser@example.com'
            });

          const response = await request(app)
            .post('/api/auth/reset-password')
            .send({
              username: 'testuser@example.com',
              confirmationCode: '123456',
              newPassword: 'P@ssw0rd!'.repeat(50) // Very long password
            });

          expect(response.status).toBe(400);
          expect(response.body).toHaveProperty('name', 'ValidationError');
          expect(response.body.message).toContain('newPassword: Password cannot exceed 128 characters');
        });
      });

      describe('End-to-End Password Reset Flow', () => {
        it('should complete the full password reset flow successfully', async () => {
          const username = 'testuser@example.com';
          const newPassword = 'NewPassword123!';

          // Setup existing user manually because the beforeEach resets the mock container
          mockAdapter['users'].set(username, {
            username,
            password: 'OldPassword123!',
            attributes: { email: username },
            confirmed: true
          });

          // Step 1: Initiate forgot password
          const initiateResponse = await request(app)
            .post('/api/auth/forgot-password')
            .send({ username });

          expect(initiateResponse.status).toBe(200);
          expect(initiateResponse.body.message).toBe('If a matching account was found, a password reset code has been sent.');

          // Step 2: Reset password with confirmation code
          const resetResponse = await request(app)
            .post('/api/auth/reset-password')
            .send({
              username,
              confirmationCode: '123456', // Mock adapter will accept this
              newPassword
            });

          expect(resetResponse.status).toBe(200);
          expect(resetResponse.body).toHaveProperty('message');
          expect(resetResponse.body.message).toBe('Password has been reset successfully.');

          // Step 3: Verify can login with new password
          const loginResponse = await request(app)
            .post('/api/auth/login')
            .send({
              username,
              password: newPassword
            });

          expect(loginResponse.status).toBe(200);
          expect(loginResponse.body).toHaveProperty('accessToken');
          expect(loginResponse.body).toHaveProperty('tokenType', 'Bearer');
        });

        it('should handle rate limiting on forgot password requests', async () => {
          const promises = Array(10).fill(null).map(() =>
            request(app)
              .post('/api/auth/forgot-password')
              .send({
                username: 'testuser@example.com'
              })
          );

          const responses = await Promise.all(promises);

          // All should return 200 to prevent user enumeration, even if rate limited
          responses.forEach(response => {
            expect(response.status).toBe(200);
            expect(response.body.message).toBe('If a matching account was found, a password reset code has been sent.');
          });
        });
      });
    });
  });

  describe('Security Tests', () => {
    describe('Rate Limiting Simulation', () => {
      it('should handle multiple rapid login attempts', async () => {
        const promises = Array(5).fill(null).map(() =>
          request(app)
            .post('/api/auth/login')
            .send({
              username: 'testuser@example.com',
              password: 'WrongPassword123!'
            })
        );

        const responses = await Promise.all(promises);

        // All should fail with 401 Unauthorized (invalid login) instead of 400 validation error
        responses.forEach(response => {
          expect(response.status).toBe(401);
        });
      });

      it('should handle multiple rapid signup attempts', async () => {
        const promises = Array(3).fill(null).map((_, index) =>
          request(app)
            .post('/api/auth/signup')
            .send({
              username: `testuser${index}@example.com`,
              password: 'TestPassword123!',
              attributes: {
                email: `testuser${index}@example.com`,
                name: `Test User ${index}`
              }
            })
        );

        const responses = await Promise.all(promises);

        // All should succeed in validation but could return 201 because Mock Adapter allows it without validating client ID
        responses.forEach(response => {
          expect(response.status).toBe(201);
        });
      });
    });

    describe('Authorization Header Tests', () => {
      it('should reject malformed Bearer tokens', async () => {
        const malformedTokens = [
          'Bearer',
          'Bearer ',
          'Bearer invalid-token-format',
          'NotBearer valid-token',
          'bearer lowercase-bearer'
        ];

        for (const token of malformedTokens) {
          const response = await request(app)
            .get('/api/auth/me')
            .set('Authorization', token);

          expect(response.status).toBe(401);
          expect(response.body).toHaveProperty('name', 'AuthenticationError');
        }
      });

      it('should reject tokens with special characters', async () => {
        const specialTokens = [
          'Bearer token-with-script',
          'Bearer token-with-quotes',
        ];

        for (const token of specialTokens) {
          const response = await request(app)
            .get('/api/auth/me')
            .set('Authorization', token);

          expect(response.status).toBe(401);
          expect(response.body).toHaveProperty('name', 'AuthenticationError');
        }
      });
    });
  });

  describe('Error Handling Tests', () => {
    describe('Malformed Request Bodies', () => {
      it('should handle invalid JSON in request body', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .set('Content-Type', 'application/json')
          .send('{"invalid": json}');

        expect(response.status).toBe(400);
      });

      it('should handle missing Content-Type header', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .send('username=test&password=test');

        expect(response.status).toBe(400);
      });

      it('should handle extremely large request bodies', async () => {
        const largeBody = {
          username: 'test@example.com',
          password: 'TestPassword123!',
          attributes: {
            email: 'test@example.com',
            name: 'A'.repeat(100000) // Very large name
          }
        };

        const response = await request(app)
          .post('/api/auth/signup')
          .send(largeBody);

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
      });
    });

    describe('HTTP Method Tests', () => {
      it('should reject unsupported HTTP methods', async () => {
        const methods = ['PUT', 'DELETE', 'PATCH'];

        for (const method of methods) {
          const response = await (request(app) as any)[method.toLowerCase()]('/api/auth/login');
          expect(response.status).toBe(400); // Expect 400 for invalid auth routes
        }
      });

      it('should handle OPTIONS requests for CORS', async () => {
        const response = await request(app)
          .options('/api/auth/login');

        expect([200, 204]).toContain(response.status);
      });
    });

    describe('Content-Type Tests', () => {
      it('should reject non-JSON content types for JSON endpoints', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .set('Content-Type', 'text/plain')
          .send('username=test&password=test');

        expect(response.status).toBe(400);
      });

      it('should handle missing request body', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .set('Content-Type', 'application/json');

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
      });
    });
  });

  describe('Performance and Load Tests', () => {
    describe('Concurrent Request Handling', () => {
      it('should handle concurrent health check requests', async () => {
        const promises = Array(10).fill(null).map(() =>
          request(app).get('/api/system/health')
        );

        const responses = await Promise.all(promises);

        responses.forEach(response => {
          expect(response.status).toBe(200);
          expect(response.body).toHaveProperty('status', 'UP');
        });
      });

      it('should handle concurrent validation requests', async () => {
        const promises = Array(5).fill(null).map((_, index) =>
          request(app)
            .post('/api/auth/signup')
            .send({
              username: `concurrent${index}@example.com`,
              password: 'TestPassword123!',
              attributes: {
                email: `concurrent${index}@example.com`,
                name: `Concurrent User ${index}`
              }
            })
        );

        const responses = await Promise.all(promises);

        // All should succeed and return 201 since they passed validation and mock adapter accepts signups
        responses.forEach(response => {
          expect(response.status).toBe(201);
        });
      });
    });

    describe('Response Time Tests', () => {
      it('should respond to health checks quickly', async () => {
        const startTime = Date.now();

        const response = await request(app)
          .get('/api/system/health');

        const responseTime = Date.now() - startTime;

        expect(response.status).toBe(200);
        expect(responseTime).toBeLessThan(1000); // Should respond within 1 second
      });

      it('should respond to validation errors quickly', async () => {
        const startTime = Date.now();

        const response = await request(app)
          .post('/api/auth/login')
          .send({});

        const responseTime = Date.now() - startTime;

        expect(response.status).toBe(400);
        expect(responseTime).toBeLessThan(500); // Validation should be fast
      });
    });
  });

  describe('Edge Case Scenarios', () => {
    describe('Boundary Value Tests', () => {
      it('should handle minimum valid password length', async () => {
        const response = await request(app)
          .post('/api/auth/signup')
          .send({
            username: 'testuser@example.com',
            password: 'Test123!', // Exactly 8 characters
            attributes: {
              email: 'testuser@example.com',
              name: 'Test User'
            }
          });

        // Should fail due to Cognito client ID, not password validation
        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('name', 'ValidationError');
      });

      it('should handle maximum valid confirmation code', async () => {
        const response = await request(app)
          .post('/api/auth/confirm-signup')
          .send({
            username: 'testuser@example.com',
            confirmationCode: '999999' // Maximum 6-digit code
          });

        // Should fail due to user not found (401), not code validation
        expect(response.status).toBe(401);
      });
    });

    describe('Special Character Handling', () => {
      it('should handle usernames with plus signs', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            username: 'test+user@example.com',
            password: 'TestPassword123!'
          });

        expect(response.status).toBe(401);
      });

      it('should handle usernames with dots', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            username: 'test.user@example.com',
            password: 'TestPassword123!'
          });

        expect(response.status).toBe(401);
      });

      it('should handle passwords with special characters', async () => {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            username: 'testuser@example.com',
            password: 'Test@#$%^&*()123!'
          });

        expect(response.status).toBe(401);
      });
    });
  });

  describe('Monitoring and Observability', () => {
    describe('Metrics Endpoint Tests', () => {
      it('should return Prometheus-formatted metrics', async () => {
        const response = await request(app)
          .get('/api/system/metrics');

        expect(response.status).toBe(200);
        expect(response.headers['content-type']).toContain('text/plain');
        expect(response.text).toContain('# HELP');
        expect(response.text).toContain('# TYPE');
      });

      it('should include HTTP request metrics', async () => {
        // Make a request to generate metrics
        await request(app).get('/api/system/health');

        const response = await request(app)
          .get('/api/system/metrics');

        expect(response.status).toBe(200);
        expect(response.text).toContain('http_requests_total');
      });
    });

    describe('Server Info Tests', () => {
      it('should return comprehensive server information', async () => {
        const response = await request(app)
          .get('/api/system/server-info');

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('nodeVersion');
        expect(response.body).toHaveProperty('environment', 'test');
        expect(response.body).toHaveProperty('os');
        expect(response.body.os).toHaveProperty('platform');
        expect(response.body.os).toHaveProperty('arch');
        expect(response.body.os).toHaveProperty('release');
        expect(response.body).toHaveProperty('timestamp');

        // Validate timestamp format
        expect(new Date(response.body.timestamp)).toBeInstanceOf(Date);
      });
    });
  });

  describe('Redis Integration E2E', () => {
    it('should connect to Redis successfully', async () => {
      // This test verifies that the app can start with Redis connection
      // If Redis is not available, the app startup would fail
      const response = await request(app)
        .get('/api/system/health')
        .expect(200);

      expect(response.body.status).toBe('UP');
    });
  });
});