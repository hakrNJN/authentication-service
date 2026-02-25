import { ChallengeNameType, CodeDeliveryDetailsType } from '@aws-sdk/client-cognito-identity-provider';
import { injectable, inject } from 'tsyringe';
import { AuthTokens, IAuthAdapter, SignUpResult } from '../../../src/application/interfaces/IAuthAdapter';
import { AuthenticationError, NotFoundError, ValidationError } from '../../../src/shared/errors/BaseError';
import { ILogger } from '../../../src/application/interfaces/ILogger';
import { TYPES } from '../../../src/shared/constants/types';

@injectable()
export class MockCognitoAdapter implements IAuthAdapter {
  private users = new Map<string, any>();
  private confirmationCodes = new Map<string, string>();
  private refreshTokens = new Map<string, string>();
  private forgotPasswordRequests = new Map<string, number>();
  private clientId: string;
  private userPoolId: string;

  constructor(@inject(TYPES.Logger) private logger: ILogger) {
    this.clientId = process.env.COGNITO_CLIENT_ID || 'testClientId123';
    this.userPoolId = process.env.COGNITO_USER_POOL_ID || 'test-user-pool-id';

    // Validate configuration
    if (!this.isValidClientId(this.clientId)) {
      throw new ValidationError('Invalid client ID configuration');
    }
    this.logger.info('MockCognitoAdapter initialized.');
  }

  private isValidClientId(clientId: string): boolean {
    // No need to validate client ID in mock adapter for testing
    return true;
  }

  async signUp(details: { username: string; password: string; attributes: Record<string, string> }): Promise<SignUpResult> {
    this.logger.debug(`MockCognitoAdapter: signUp called for username: ${details.username}`);
    const { username, password, attributes } = details;
    if (this.users.has(username)) {
      this.logger.warn(`MockCognitoAdapter: signUp failed, username already exists: ${username}`);
      throw new ValidationError('Username already exists');
    }

    const userSub = `mock-user-${Date.now()}`;
    this.users.set(username, {
      username,
      password,
      attributes,
      userSub,
      confirmed: false
    });
    this.logger.debug(`MockCognitoAdapter: User ${username} added to internal map. Current users: ${Array.from(this.users.keys())}`);

    // Generate mock confirmation code
    this.confirmationCodes.set(username, '123456');
    this.logger.debug(`MockCognitoAdapter: Confirmation code set for ${username}.`);

    return {
      userSub,
      userConfirmed: false
    };
  }

  async confirmSignUp(username: string, confirmationCode: string): Promise<void> {
    this.logger.debug(`MockCognitoAdapter: confirmSignUp called for username: ${username}, code: ${confirmationCode}`);
    const user = this.users.get(username);
    if (!user) {
      this.logger.warn(`MockCognitoAdapter: confirmSignUp failed, user not found: ${username}`);
      throw new NotFoundError('User');
    }
    this.logger.debug(`MockCognitoAdapter: User found for confirmSignUp: ${username}, confirmed status: ${user.confirmed}`);

    const expectedCode = this.confirmationCodes.get(username);
    if (confirmationCode !== expectedCode) {
      this.logger.warn(`MockCognitoAdapter: confirmSignUp failed, invalid code for ${username}. Expected: ${expectedCode}, Received: ${confirmationCode}`);
      throw new ValidationError('Invalid verification code');
    }

    user.confirmed = true;
    this.confirmationCodes.delete(username);
    this.logger.debug(`MockCognitoAdapter: User ${username} confirmed. Confirmation code deleted. Current users: ${Array.from(this.users.keys())}`);
  }

  async authenticateUser(username: string, password: string): Promise<AuthTokens> {
    const user = this.users.get(username);
    if (!user || user.password !== password) {
      throw new AuthenticationError('Incorrect username or password');
    }

    if (!user.confirmed) {
      throw new AuthenticationError('User is not confirmed');
    }

    // For simplicity, mock doesn't handle MFA challenges in authenticateUser
    // MFA would be handled via respondToAuthChallenge

    const accessToken = `mock-access-token-${Date.now()}`;
    const refreshToken = `mock-refresh-token-${Date.now()}`;

    this.refreshTokens.set(refreshToken, username);

    return {
      accessToken,
      refreshToken,
      expiresIn: 3600,
      tokenType: 'Bearer'
    };
  }

  async login(username?: string, password?: string): Promise<AuthTokens> {
    if (!username || !password) {
      throw new AuthenticationError('Username and password are required.');
    }
    return this.authenticateUser(username, password);
  }

  async respondToAuthChallenge(username: string, session: string, challengeName: ChallengeNameType, responses: Record<string, string>): Promise<AuthTokens> {
    const user = this.users.get(username);
    if (!user) {
      throw new NotFoundError('User');
    }

    // Simple mock validation
    if (challengeName === ChallengeNameType.SMS_MFA && responses.SMS_MFA_CODE !== '123456') {
      throw new ValidationError('Invalid MFA code');
    }

    const accessToken = `mock-access-token-${Date.now()}`;
    const refreshToken = `mock-refresh-token-${Date.now()}`;

    this.refreshTokens.set(refreshToken, username);

    return {
      accessToken,
      refreshToken,
      expiresIn: 3600,
      tokenType: 'Bearer'
    };
  }

  async refreshToken(refreshToken: string): Promise<AuthTokens> {
    const username = this.refreshTokens.get(refreshToken);
    if (!username) {
      throw new AuthenticationError('Invalid refresh token');
    }

    const newAccessToken = `mock-access-token-${Date.now()}`;

    return {
      accessToken: newAccessToken,
      expiresIn: 3600,
      tokenType: 'Bearer'
    };
  }

  async getUserFromToken(accessToken: string): Promise<Record<string, any>> {
    // Simple mock validation
    if (!accessToken.startsWith('mock-access-token-')) {
      throw new AuthenticationError('Invalid access token');
    }

    return {
      username: 'mockuser',
      attributes: {
        email: 'mock@example.com',
        name: 'Mock User'
      },
      userSub: 'mock-user-sub'
    };
  }

  async signOut(accessToken: string): Promise<void> {
    // Mock implementation - just validate token format
    if (!accessToken.startsWith('mock-access-token-')) {
      throw new AuthenticationError('Invalid access token');
    }
    // In real implementation, this would invalidate the token
  }



  async initiateForgotPassword(username: string): Promise<CodeDeliveryDetailsType | undefined> {
    this.logger.debug(`MockCognitoAdapter: initiateForgotPassword called for username: ${username}`);
    const user = this.users.get(username);

    // If user does not exist, we can't initiate a password reset.
    if (!user) {
      this.logger.info(`MockCognitoAdapter: initiateForgotPassword - User ${username} not found. Returning undefined to prevent enumeration.`);
      return undefined;
    }

    // Generate a mock confirmation code and track the request
    this.confirmationCodes.set(username, '123456');
    this.forgotPasswordRequests.set(username, Date.now());
    this.logger.debug(`MockCognitoAdapter: Forgot password request initiated for ${username}. Code set. Current forgotPasswordRequests: ${Array.from(this.forgotPasswordRequests.keys())}`);


    // Simulate code delivery details
    return {
      AttributeName: 'email',
      DeliveryMedium: 'EMAIL',
      Destination: user.attributes.email
    };
  }

  async confirmForgotPassword(username: string, confirmationCode: string, newPassword: string): Promise<void> {
    this.logger.debug(`MockCognitoAdapter: confirmForgotPassword called for username: ${username}, code: ${confirmationCode}`);
    const user = this.users.get(username);
    const storedCode = this.confirmationCodes.get(username);
    this.logger.debug(`MockCognitoAdapter: confirmForgotPassword - User exists: ${!!user}, Stored code exists: ${!!storedCode}, Forgot password request exists: ${this.forgotPasswordRequests.has(username)}`);


    // For security reasons, check if there was a password reset request initiated
    if (!storedCode) {
      this.logger.warn(`MockCognitoAdapter: confirmForgotPassword failed - No stored code for ${username}.`);
      throw new ValidationError('No password reset request was initiated for this user');
    }

    // For testing purposes, always accept '123456' as valid
    if (confirmationCode !== storedCode) {
      this.logger.warn(`MockCognitoAdapter: confirmForgotPassword failed - Invalid code for ${username}. Expected: ${storedCode}, Received: ${confirmationCode}`);
      throw new ValidationError('Invalid verification code provided, please try again.');
    }

    // Verify we have a pending forgot password request
    if (!this.forgotPasswordRequests.has(username)) {
      this.logger.warn(`MockCognitoAdapter: confirmForgotPassword failed - No pending forgot password request for ${username}.`);
      throw new ValidationError('Password reset request has expired or was never initiated');
    }

    // At this point we can validate the user exists since we have a valid code
    if (!user) {
      this.logger.error(`MockCognitoAdapter: confirmForgotPassword failed - User ${username} not found in internal map despite valid code and request.`);
      throw new ValidationError('User not found');
    }

    // Validate password complexity
    if (!this.validatePassword(newPassword)) {
      this.logger.warn(`MockCognitoAdapter: confirmForgotPassword failed - New password for ${username} does not meet complexity requirements.`);
      throw new ValidationError('Password does not meet complexity requirements');
    }

    // Update password and clean up
    user.password = newPassword;
    this.confirmationCodes.delete(username);
    this.forgotPasswordRequests.delete(username);
    this.logger.debug(`MockCognitoAdapter: Password successfully reset for ${username}. Cleaned up codes and requests.`);
  }

  // Helper method to validate password complexity
  private validatePassword(password: string): boolean {
    const minLength = 8;
    const maxLength = 256;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return password.length >= minLength &&
      password.length <= maxLength &&
      hasUpper && hasLower && hasNumber && hasSpecial;
  }

  async changePassword(accessToken: string, previousPassword: string, proposedPassword: string): Promise<void> {
    // Mock implementation
    if (!accessToken.startsWith('mock-access-token-')) {
      throw new AuthenticationError('Invalid access token');
    }

    // In a real implementation, we'd validate the old password and update it
  }

  async adminInitiateForgotPassword(username: string): Promise<void> {
    const user = this.users.get(username);
    if (!user) {
      throw new NotFoundError('User');
    }
    // Mock implementation - just validate user exists
  }

  async adminSetPassword(username: string, newPassword: string): Promise<void> {
    const user = this.users.get(username);
    if (!user) {
      throw new NotFoundError('User');
    }

    user.password = newPassword;
  }

  reset(): void {
    this.logger.debug('MockCognitoAdapter: Resetting all internal data (users, codes, tokens, requests).');
    this.users.clear();
    this.confirmationCodes.clear();
    this.refreshTokens.clear();
    this.forgotPasswordRequests.clear();
  }
}