import { ChallengeNameType, CodeDeliveryDetailsType } from '@aws-sdk/client-cognito-identity-provider';
import { injectable } from 'tsyringe';
import { AuthTokens, IAuthAdapter, SignUpResult } from '../../../src/application/interfaces/IAuthAdapter';
import { ValidationError, NotFoundError, AuthenticationError } from '../../../src/shared/errors/BaseError';

@injectable()
export class MockCognitoAdapter implements IAuthAdapter {
  private users = new Map<string, any>();
  private confirmationCodes = new Map<string, string>();
  private refreshTokens = new Map<string, string>();
  private forgotPasswordRequests = new Map<string, number>();
  private clientId: string;
  private userPoolId: string;

  constructor() {
    this.clientId = process.env.COGNITO_CLIENT_ID || 'testClientId123';
    this.userPoolId = process.env.COGNITO_USER_POOL_ID || 'test-user-pool-id';

    // Validate configuration
    if (!this.isValidClientId(this.clientId)) {
      throw new ValidationError('Invalid client ID configuration');
    }
  }

  private isValidClientId(clientId: string): boolean {
    // No need to validate client ID in mock adapter for testing
    return true;
  }

  async signUp(details: { username: string; password: string; attributes: Record<string, string> }): Promise<SignUpResult> {
    const { username, password, attributes } = details;
    if (this.users.has(username)) {
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

    // Generate mock confirmation code
    this.confirmationCodes.set(username, '123456');

    return {
      userSub,
      userConfirmed: false
    };
  }

  async confirmSignUp(username: string, confirmationCode: string): Promise<void> {
    const user = this.users.get(username);
    if (!user) {
      throw new NotFoundError('User');
    }

    const expectedCode = this.confirmationCodes.get(username);
    if (confirmationCode !== expectedCode) {
      throw new ValidationError('Invalid verification code');
    }

    user.confirmed = true;
    this.confirmationCodes.delete(username);
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
    return undefined;
  }

  async confirmForgotPassword(username: string, confirmationCode: string, newPassword: string): Promise<void> {
    const user = this.users.get(username);
    if (!user) {
      // For security reasons, don't throw an error if the user is not found.
      // This prevents user enumeration attacks.
      return;
    }

    const storedCode = this.confirmationCodes.get(username);
    if (!storedCode || confirmationCode !== storedCode) {
      throw new AuthenticationError('Invalid verification code provided, please try again.');
    }

    // Validate password complexity
    if (!this.validatePassword(newPassword)) {
      throw new ValidationError('Password does not meet complexity requirements');
    }

    user.password = newPassword;
    this.confirmationCodes.delete(username);
    this.forgotPasswordRequests.delete(username);
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
}