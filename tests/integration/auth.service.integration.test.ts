import 'reflect-metadata';
import { AuthService } from '../../src/application/services/auth.service';
import { IAuthAdapter } from '../../src/application/interfaces/IAuthAdapter';
import { ILogger } from '../../src/application/interfaces/ILogger';
import { IConfigService } from '../../src/application/interfaces/IConfigService';
import { ITokenBlacklistService } from '../../src/application/interfaces/ITokenBlacklistService';
import { ChallengeNameType } from '@aws-sdk/client-cognito-identity-provider';
import { MfaRequiredError } from '../../src/domain/exceptions/AuthenticationError';
import * as jwt from 'jsonwebtoken';

// Mock dependencies
const mockAuthAdapter: jest.Mocked<any> = {
  signUp: jest.fn(),
  confirmSignUp: jest.fn(),
  authenticateUser: jest.fn(),
  respondToAuthChallenge: jest.fn(),
  refreshToken: jest.fn(),
  getUserFromToken: jest.fn(),
  signOut: jest.fn(),
  initiateForgotPassword: jest.fn(),
  confirmForgotPassword: jest.fn(),
  changePassword: jest.fn(),
  adminInitiateForgotPassword: jest.fn(),
  adminSetPassword: jest.fn(),
  getAuthMode: jest.fn(),
  login: jest.fn(),
  validateToken: jest.fn()
};

const mockEventBus = {
  publish: jest.fn().mockResolvedValue(undefined),
  subscribe: jest.fn(),
  unsubscribe: jest.fn()
};

const mockLogger: jest.Mocked<ILogger> = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn()
};

const mockConfigService: jest.Mocked<IConfigService> = {
  get: jest.fn(),
  getNumber: jest.fn(),
  getBoolean: jest.fn(),
  getAllConfig: jest.fn(),
  has: jest.fn(),
  getOrThrow: jest.fn()
};

const mockTokenBlacklistService = {
  addToBlacklist: jest.fn(),
  isBlacklisted: jest.fn().mockResolvedValue(false),
  disconnect: jest.fn()
};

describe('Comprehensive Authentication Integration Tests', () => {
  let authService: AuthService;

  beforeEach(() => {
    jest.clearAllMocks();
    mockEventBus.publish.mockResolvedValue(undefined);
    authService = new AuthService(mockLogger, mockConfigService, mockAuthAdapter, mockTokenBlacklistService, mockEventBus);
  });

  describe('Complete Authentication Flow', () => {
    it('should complete full signup and login flow', async () => {
      const username = 'testuser@example.com';
      const password = 'TestPassword123!';
      const attributes = { email: username, name: 'Test User' };

      // Step 1: Sign up
      mockAuthAdapter.signUp.mockResolvedValue({
        userSub: 'user-123',
        userConfirmed: false
      });

      const signupResult = await authService.signUp({ username, password, attributes });
      expect(signupResult.userSub).toBe('user-123');
      expect(signupResult.userConfirmed).toBe(false);

      // Step 2: Confirm signup
      mockAuthAdapter.confirmSignUp.mockResolvedValue();

      await authService.confirmSignUp(username, '123456');
      expect(mockAuthAdapter.confirmSignUp).toHaveBeenCalledWith(username, '123456');

      // Step 3: Login
      mockAuthAdapter.login.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      const loginResult = await authService.login(username, password);
      expect(loginResult.accessToken).toBe('access-token');
      expect(loginResult.refreshToken).toBe('refresh-token');
    });

    it('should handle MFA flow during login', async () => {
      const username = 'testuser@example.com';
      const password = 'TestPassword123!';

      // Step 1: Login returns MFA challenge
      // Step 1: Login throws MFA challenge
      const mfaError = new MfaRequiredError('mfa-session', ChallengeNameType.SMS_MFA, { CODE_DELIVERY_DESTINATION: '+1***5678' });
      mockAuthAdapter.login.mockRejectedValue(mfaError);

      await expect(authService.login(username, password)).rejects.toThrow(MfaRequiredError);

      // Verify the error has the expected properties
      try {
        await authService.login(username, password);
      } catch (error: any) {
        expect(error.challengeName).toBe(ChallengeNameType.SMS_MFA);
        expect(error.session).toBe('mfa-session');
      }

      // Step 2: Verify MFA
      mockAuthAdapter.respondToAuthChallenge.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      const mfaResult = await authService.verifyMfa(username, 'mfa-session', ChallengeNameType.SMS_MFA, '123456');
      expect(mfaResult.accessToken).toBe('access-token');
    });

    it('should handle NEW_PASSWORD_REQUIRED challenge', async () => {
      const username = 'testuser@example.com';
      const tempPassword = 'TempPassword123!';

      // Step 1: Login throws NEW_PASSWORD_REQUIRED challenge
      const passwordError = new MfaRequiredError('password-session', ChallengeNameType.NEW_PASSWORD_REQUIRED, {
        USER_ATTRIBUTES: '{"email":"testuser@example.com"}',
        requiredAttributes: '[]'
      });
      mockAuthAdapter.login.mockRejectedValue(passwordError);

      await expect(authService.login(username, tempPassword)).rejects.toThrow(MfaRequiredError);

      // Verify the error has the expected properties
      try {
        await authService.login(username, tempPassword);
      } catch (error: any) {
        expect(error.challengeName).toBe(ChallengeNameType.NEW_PASSWORD_REQUIRED);
      }

      // Step 2: Set new password
      mockAuthAdapter.respondToAuthChallenge.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      const newPasswordResult = await authService.verifyMfa(
        username,
        'password-session',
        ChallengeNameType.NEW_PASSWORD_REQUIRED,
        'NewPassword123!'
      );
      expect(newPasswordResult.accessToken).toBe('access-token');
    });

    it('should handle SOFTWARE_TOKEN_MFA challenge', async () => {
      const username = 'testuser@example.com';
      const password = 'TestPassword123!';

      // Step 1: Login throws SOFTWARE_TOKEN_MFA challenge
      const totpError = new MfaRequiredError('totp-session', ChallengeNameType.SOFTWARE_TOKEN_MFA, {});
      mockAuthAdapter.login.mockRejectedValue(totpError);

      await expect(authService.login(username, password)).rejects.toThrow(MfaRequiredError);

      // Verify the error has the expected properties
      try {
        await authService.login(username, password);
      } catch (error: any) {
        expect(error.challengeName).toBe(ChallengeNameType.SOFTWARE_TOKEN_MFA);
      }

      // Step 2: Verify TOTP code
      mockAuthAdapter.respondToAuthChallenge.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      const totpResult = await authService.verifyMfa(
        username,
        'totp-session',
        ChallengeNameType.SOFTWARE_TOKEN_MFA,
        '123456'
      );
      expect(totpResult.accessToken).toBe('access-token');
    });
  });

  describe('Token Management Integration', () => {
    it('should handle token refresh and blacklisting', async () => {
      const refreshToken = 'refresh-token';
      const oldAccessToken = jwt.sign({ jti: 'test-jti', exp: Math.floor(Date.now() / 1000) + 60 }, 'secret');

      // Mock token refresh
      mockAuthAdapter.refreshToken.mockResolvedValue({
        accessToken: 'new-access-token',
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      const result = await authService.refresh(refreshToken);
      expect(result.accessToken).toBe('new-access-token');

      // Mock logout (should blacklist token)
      mockAuthAdapter.signOut.mockResolvedValue(undefined);
      mockTokenBlacklistService.addToBlacklist.mockResolvedValue(undefined);

      await authService.signOut(oldAccessToken);
      expect(mockTokenBlacklistService.addToBlacklist).toHaveBeenCalledWith(
        'test-jti',
        expect.any(Number)
      );
    });

    it('should check token blacklist before operations', async () => {
      const accessToken = 'blacklisted-token';

      // Mock token as blacklisted
      mockTokenBlacklistService.isBlacklisted.mockResolvedValue(true);

      await expect(authService.getUserInfo(accessToken))
        .rejects.toThrow('Token has been invalidated');

      expect(mockTokenBlacklistService.isBlacklisted).toHaveBeenCalledWith(accessToken);
    });

    it('should handle token refresh with partial response', async () => {
      const refreshToken = 'refresh-token';

      // Mock token refresh without refresh token in response
      mockAuthAdapter.refreshToken.mockResolvedValue({
        accessToken: 'new-access-token',
        expiresIn: 3600,
        tokenType: 'Bearer'
        // No refreshToken in response
      });

      const result = await authService.refresh(refreshToken);
      expect(result.accessToken).toBe('new-access-token');
      expect(result.refreshToken).toBeUndefined();
    });

    it('should handle getUserInfo with valid token', async () => {
      const accessToken = 'valid-access-token';

      // Mock token as not blacklisted
      mockTokenBlacklistService.isBlacklisted.mockResolvedValue(false);
      mockAuthAdapter.getUserFromToken.mockResolvedValue({
        username: 'testuser',
        userSub: 'user-123',
        attributes: {
          email: 'testuser@example.com',
          name: 'Test User'
        }
      });

      const result = await authService.getUserInfo(accessToken);
      expect(result.username).toBe('testuser');
      expect(result.userSub).toBe('user-123');
      expect(result.attributes.email).toBe('testuser@example.com');
    });
  });

  describe('Password Management Integration', () => {
    it('should complete forgot password flow', async () => {
      const username = 'testuser@example.com';
      const newPassword = 'NewPassword123!';
      const confirmationCode = '123456';

      // Step 1: Initiate forgot password
      mockAuthAdapter.initiateForgotPassword.mockResolvedValue({
        Destination: 't***@example.com',
        DeliveryMedium: 'EMAIL'
      });

      const initiateResult = await authService.initiateForgotPassword(username);
      expect(initiateResult?.Destination).toBe('t***@example.com');

      // Step 2: Confirm forgot password
      mockAuthAdapter.confirmForgotPassword.mockResolvedValue(undefined);

      await authService.confirmForgotPassword(username, confirmationCode, newPassword);
      expect(mockAuthAdapter.confirmForgotPassword).toHaveBeenCalledWith(
        username,
        confirmationCode,
        newPassword
      );
    });

    it('should handle password change for authenticated user', async () => {
      const accessToken = 'valid-access-token';
      const oldPassword = 'OldPassword123!';
      const newPassword = 'NewPassword123!';

      // Mock token as not blacklisted
      mockTokenBlacklistService.isBlacklisted.mockResolvedValue(false);
      mockAuthAdapter.changePassword.mockResolvedValue(undefined);

      await authService.changePassword(accessToken, oldPassword, newPassword);
      expect(mockAuthAdapter.changePassword).toHaveBeenCalledWith(
        accessToken,
        oldPassword,
        newPassword
      );
    });

    it('should handle forgot password without code delivery details', async () => {
      const username = 'testuser@example.com';

      // Mock forgot password without delivery details
      mockAuthAdapter.initiateForgotPassword.mockResolvedValue(undefined);

      const result = await authService.initiateForgotPassword(username);
      expect(result).toBeUndefined();
    });
  });

  describe('Error Handling Integration', () => {
    it('should handle adapter errors gracefully', async () => {
      const username = 'testuser@example.com';
      const password = 'TestPassword123!';

      // Mock adapter throwing error
      mockAuthAdapter.login.mockRejectedValue(new Error('Cognito error'));

      await expect(authService.login(username, password))
        .rejects.toThrow('Login failed: Cognito error');

      expect(mockLogger.error).toHaveBeenCalledWith(
        `Login failed for user ${username}: Cognito error`,
        expect.any(Error)
      );
    });

    it('should handle blacklist service errors', async () => {
      const accessToken = 'test-token';

      // Mock blacklist service throwing error
      mockTokenBlacklistService.isBlacklisted.mockRejectedValue(new Error('Redis error'));

      await expect(authService.getUserInfo(accessToken))
        .rejects.toThrow('Failed to retrieve user info: Redis error');
    });

    it('should handle signup confirmation errors', async () => {
      const username = 'testuser@example.com';
      const confirmationCode = '123456';

      // Mock adapter throwing error
      mockAuthAdapter.confirmSignUp.mockRejectedValue(new Error('Invalid code'));

      await expect(authService.confirmSignUp(username, confirmationCode))
        .rejects.toThrow('Confirmation failed: Invalid code');

      expect(mockLogger.error).toHaveBeenCalledWith(
        `Signup confirmation failed for ${username}: Invalid code`,
        expect.any(Error)
      );
    });

    it('should handle MFA verification errors', async () => {
      const username = 'testuser@example.com';
      const session = 'mfa-session';
      const challengeName = ChallengeNameType.SMS_MFA;
      const code = '123456';

      // Mock adapter throwing error
      mockAuthAdapter.respondToAuthChallenge.mockRejectedValue(new Error('Invalid MFA code'));

      await expect(authService.verifyMfa(username, session, challengeName, code))
        .rejects.toThrow('MFA verification failed: Invalid MFA code');

      expect(mockLogger.error).toHaveBeenCalledWith(
        `MFA verification failed for user ${username}: Invalid MFA code`,
        expect.any(Error)
      );
    });

    it('should handle token refresh errors', async () => {
      const refreshToken = 'invalid-refresh-token';

      // Mock adapter throwing error
      mockAuthAdapter.refreshToken.mockRejectedValue(new Error('Invalid refresh token'));

      await expect(authService.refresh(refreshToken))
        .rejects.toThrow('Token refresh failed: Invalid refresh token');

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Token refresh failed: Invalid refresh token',
        expect.any(Error)
      );
    });

    it('should handle signout errors', async () => {
      const accessToken = 'test-token';

      // Mock blacklist service success but adapter error
      mockTokenBlacklistService.addToBlacklist.mockResolvedValue(undefined);
      mockAuthAdapter.signOut.mockRejectedValue(new Error('Signout failed'));

      await expect(authService.signOut(accessToken))
        .rejects.toThrow('Logout failed: Signout failed');

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Logout failed: Signout failed',
        expect.any(Error)
      );
    });

    it('should handle change password errors', async () => {
      const accessToken = 'valid-access-token';
      const oldPassword = 'OldPassword123!';
      const newPassword = 'NewPassword123!';

      // Mock token as not blacklisted but change password fails
      mockTokenBlacklistService.isBlacklisted.mockResolvedValue(false);
      mockAuthAdapter.changePassword.mockRejectedValue(new Error('Password change failed'));

      await expect(authService.changePassword(accessToken, oldPassword, newPassword))
        .rejects.toThrow('Password change failed: Password change failed');

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Password change failed: Password change failed',
        expect.any(Error)
      );
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle empty username and password', async () => {
      const username = '';
      const password = '';

      mockAuthAdapter.login.mockRejectedValue(new Error('Invalid credentials'));

      await expect(authService.login(username, password))
        .rejects.toThrow('Username and password are required.');
    });

    it('should handle very long tokens', async () => {
      const longToken = 'a'.repeat(10000);

      mockTokenBlacklistService.isBlacklisted.mockResolvedValue(false);
      mockAuthAdapter.getUserFromToken.mockResolvedValue({
        username: 'testuser',
        userSub: 'user-123',
        attributes: {}
      });

      const result = await authService.getUserInfo(longToken);
      expect(result.username).toBe('testuser');
    });

    it('should handle signup with minimal attributes', async () => {
      const username = 'testuser@example.com';
      const password = 'TestPassword123!';
      const attributes = { email: 'testuser@example.com' };

      mockAuthAdapter.signUp.mockResolvedValue({
        userSub: 'user-123',
        userConfirmed: true
      });

      const result = await authService.signUp({ username, password, attributes });
      expect(result.userSub).toBe('user-123');
      expect(result.userConfirmed).toBe(true);
    });

    it('should handle concurrent token operations', async () => {
      const accessToken = 'test-token';

      // Mock concurrent operations
      mockTokenBlacklistService.isBlacklisted.mockResolvedValue(false);
      mockAuthAdapter.getUserFromToken.mockResolvedValue({
        username: 'testuser',
        userSub: 'user-123',
        attributes: {}
      });

      // Execute multiple operations concurrently
      const promises = [
        authService.getUserInfo(accessToken),
        authService.getUserInfo(accessToken),
        authService.getUserInfo(accessToken)
      ];

      const results = await Promise.all(promises);
      expect(results).toHaveLength(3);
      results.forEach(result => {
        expect(result.username).toBe('testuser');
      });
    });
  });

  describe('Logging Integration', () => {
    it('should log successful operations', async () => {
      const username = 'testuser@example.com';
      const password = 'TestPassword123!';

      mockAuthAdapter.login.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      await authService.login(username, password);

      expect(mockLogger.info).toHaveBeenCalledWith(`Login successful for user: ${username}`);
    });

    it('should log MFA challenges', async () => {
      const username = 'testuser@example.com';
      const password = 'TestPassword123!';

      const mfaError = new MfaRequiredError('mfa-session', ChallengeNameType.SMS_MFA, {});
      mockAuthAdapter.login.mockRejectedValue(mfaError);

      await expect(authService.login(username, password)).rejects.toThrow(MfaRequiredError);

      expect(mockLogger.warn).toHaveBeenCalledWith(
        `MFA required for user ${username}: ${ChallengeNameType.SMS_MFA}`
      );
    });

    it('should log token blacklisting', async () => {
      const accessToken = 'test-token';

      mockTokenBlacklistService.addToBlacklist.mockResolvedValue(undefined);
      mockAuthAdapter.signOut.mockResolvedValue(undefined);

      await authService.signOut(accessToken);

      expect(mockLogger.info).toHaveBeenCalledWith('Logout successful.');
    });
  });

  describe('Service Integration with Multiple Dependencies', () => {
    it('should handle complex flow with all services', async () => {
      const username = 'testuser@example.com';
      const password = 'TestPassword123!';
      const attributes = { email: username, name: 'Test User' };
      const accessToken = jwt.sign({ jti: 'complex-flow-jti', exp: Math.floor(Date.now() / 1000) + 60 }, 'secret');

      // Complete flow: signup -> confirm -> login -> get user info -> logout

      // 1. Signup
      mockAuthAdapter.signUp.mockResolvedValue({
        userSub: 'user-123',
        userConfirmed: false
      });

      await authService.signUp({ username, password, attributes });

      // 2. Confirm
      mockAuthAdapter.confirmSignUp.mockResolvedValue(undefined);
      await authService.confirmSignUp(username, '123456');

      // 3. Login
      mockAuthAdapter.login.mockResolvedValue({
        accessToken,
        refreshToken: 'refresh-token',
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      const loginResult = await authService.login(username, password);

      // 4. Get user info
      mockTokenBlacklistService.isBlacklisted.mockResolvedValue(false);
      mockAuthAdapter.getUserFromToken.mockResolvedValue({
        username,
        userSub: 'user-123',
        attributes
      });

      const userInfo = await authService.getUserInfo(loginResult.accessToken);

      // 5. Logout
      mockTokenBlacklistService.addToBlacklist.mockResolvedValue(undefined);
      mockAuthAdapter.signOut.mockResolvedValue(undefined);

      await authService.signOut(loginResult.accessToken);

      // Verify all operations completed successfully
      expect(userInfo.username).toBe(username);
      expect(mockTokenBlacklistService.addToBlacklist).toHaveBeenCalledWith('complex-flow-jti', expect.any(Number));
      expect(mockLogger.info).toHaveBeenCalledWith('Logout successful.');
    });

    it('should handle service failures gracefully in complex flows', async () => {
      const username = 'testuser@example.com';
      const password = 'TestPassword123!';

      // Start login flow
      mockAuthAdapter.login.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      const loginResult = await authService.login(username, password);

      // Blacklist service fails during getUserInfo
      mockTokenBlacklistService.isBlacklisted.mockRejectedValue(new Error('Redis connection failed'));

      await expect(authService.getUserInfo(loginResult.accessToken))
        .rejects.toThrow('Failed to retrieve user info: Redis connection failed');

      // But logout should still work if blacklist service recovers
      mockTokenBlacklistService.addToBlacklist.mockResolvedValue(undefined);
      mockAuthAdapter.signOut.mockResolvedValue(undefined);

      await expect(authService.signOut(loginResult.accessToken))
        .resolves.not.toThrow();
    });
  });
});