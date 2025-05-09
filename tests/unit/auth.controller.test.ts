import { ChallengeNameType } from '@aws-sdk/client-cognito-identity-provider';
import { AuthController } from '../../src/api/controllers/auth.controller';
import { IAuthService } from '../../src/application/interfaces/IAuthService';
import { container } from '../../src/container';
import { AuthenticationError, MfaRequiredError, ValidationError } from '../../src/domain';
import { TYPES } from '../../src/shared/constants/types';
import { mockLogger } from '../mocks/mockLogger';

const mockRequest = (body: any = {}, headers: any = {}): any => ({ body, headers });
const mockResponse = (): any => {
  const res: any = {};
  res.status = jest.fn().mockReturnThis();
  res.json = jest.fn().mockReturnThis();
  res.send = jest.fn().mockReturnThis();
  return res;
};
const mockNext = jest.fn();

describe('AuthController', () => {
  let controller: AuthController;
  let mockAuthService: jest.Mocked<IAuthService>;

  beforeEach(() => {
    jest.clearAllMocks();

    mockAuthService = {
      login: jest.fn(),
      verifyMfa: jest.fn(),
      refresh: jest.fn(),
      getUserInfo: jest.fn(),
      signUp: jest.fn(),
      confirmSignUp: jest.fn(),
      logout: jest.fn(),
      initiateForgotPassword: jest.fn(),
      confirmForgotPassword: jest.fn(),
      changePassword: jest.fn(),
    } as jest.Mocked<IAuthService>;

    if (container.isRegistered(TYPES.AuthService)) {
      container.clearInstances();
    }
    container.registerInstance<IAuthService>(TYPES.AuthService, mockAuthService);

    controller = new AuthController(mockAuthService, mockLogger);
  });

  describe('login', () => {
    it('should return tokens on successful login', async () => {
      const req = mockRequest({ username: 'user', password: 'pass' });
      const res = mockResponse();
      const tokens = { accessToken: 'access_token', refreshToken: 'refresh_token', expiresIn: 3600, tokenType: 'Bearer' };
      mockAuthService.login.mockResolvedValue(tokens);

      await controller.login(req, res, mockNext);

      expect(mockAuthService.login).toHaveBeenCalledWith('user', 'pass');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(tokens);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should call next with MfaRequiredError if MFA is required', async () => {
      const req = mockRequest({ username: 'user', password: 'pass' });
      const res = mockResponse();
      const mfaError = new MfaRequiredError('session123', ChallengeNameType.SMS_MFA, {});
      mockAuthService.login.mockRejectedValue(mfaError);

      await controller.login(req, res, mockNext);

      expect(mockAuthService.login).toHaveBeenCalledWith('user', 'pass');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(mfaError);
    });

    it('should call next with error on login failure', async () => {
      const req = mockRequest({ username: 'user', password: 'pass' });
      const res = mockResponse();
      const error = new AuthenticationError('Invalid credentials');
      mockAuthService.login.mockRejectedValue(error);

      await controller.login(req, res, mockNext);

      expect(mockAuthService.login).toHaveBeenCalledWith('user', 'pass');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });

  describe('verifyMfa', () => {
    it('should return tokens on successful MFA verification', async () => {
      const req = mockRequest({
        username: 'user',
        session: 'session123',
        challengeName: ChallengeNameType.SMS_MFA,
        code: '123456',
      });
      const res = mockResponse();
      const tokens = { accessToken: 'new_access_token', refreshToken: 'new_refresh_token', expiresIn: 3600, tokenType: 'Bearer' };
      mockAuthService.verifyMfa.mockResolvedValue(tokens);

      await controller.verifyMfa(req, res, mockNext);

      expect(mockAuthService.verifyMfa).toHaveBeenCalledWith('user', 'session123', ChallengeNameType.SMS_MFA, '123456');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(tokens);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should call next with error on MFA verification failure', async () => {
      const req = mockRequest({
        username: 'user',
        session: 'session123',
        challengeName: ChallengeNameType.SMS_MFA,
        code: 'wrongcode',
      });
      const res = mockResponse();
      const error = new AuthenticationError('Invalid MFA code.');
      mockAuthService.verifyMfa.mockRejectedValue(error);

      await controller.verifyMfa(req, res, mockNext);

      expect(mockAuthService.verifyMfa).toHaveBeenCalledWith('user', 'session123', ChallengeNameType.SMS_MFA, 'wrongcode');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });

  describe('refresh', () => {
    it('should return new tokens on successful refresh', async () => {
      const req = mockRequest({ refreshToken: 'old_refresh_token' });
      const res = mockResponse();
      const tokens = { accessToken: 'new_access_token', expiresIn: 3600, tokenType: 'Bearer' };
      mockAuthService.refresh.mockResolvedValue(tokens);

      await controller.refresh(req, res, mockNext);

      expect(mockAuthService.refresh).toHaveBeenCalledWith('old_refresh_token');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(tokens);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should call next with error on refresh failure', async () => {
      const req = mockRequest({ refreshToken: 'invalid_token' });
      const res = mockResponse();
      const error = new AuthenticationError('Invalid refresh token.');
      mockAuthService.refresh.mockRejectedValue(error);

      await controller.refresh(req, res, mockNext);

      expect(mockAuthService.refresh).toHaveBeenCalledWith('invalid_token');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });

  describe('getUserInfo', () => {
    it('should return user info on success', async () => {
      const req = mockRequest({}, { authorization: 'Bearer valid_token' });
      const res = mockResponse();
      const userInfo = { sub: 'uuid', email: 'a@b.com' };
      mockAuthService.getUserInfo.mockResolvedValue(userInfo);

      await controller.getUserInfo(req, res, mockNext);

      expect(mockAuthService.getUserInfo).toHaveBeenCalledWith('valid_token');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(userInfo);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should call next with AuthenticationError if auth header is missing', async () => {
      const req = mockRequest({}, {});
      const res = mockResponse();

      await controller.getUserInfo(req, res, mockNext);

      expect(mockAuthService.getUserInfo).not.toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ message: 'Authorization header missing or invalid' }));
    });

    it('should call next with AuthenticationError if auth header is not Bearer', async () => {
      const req = mockRequest({}, { authorization: 'Basic somecreds' });
      const res = mockResponse();

      await controller.getUserInfo(req, res, mockNext);

      expect(mockAuthService.getUserInfo).not.toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ message: 'Authorization header missing or invalid' }));
    });

    it('should call next with error on service failure', async () => {
      const req = mockRequest({}, { authorization: 'Bearer invalid_token' });
      const res = mockResponse();
      const error = new AuthenticationError('Invalid token.');
      mockAuthService.getUserInfo.mockRejectedValue(error);

      await controller.getUserInfo(req, res, mockNext);

      expect(mockAuthService.getUserInfo).toHaveBeenCalledWith('invalid_token');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });

  describe('signUp', () => {
    it('should return signup result on success', async () => {
      const signUpDetails = { username: 'newuser', password: 'password123', attributes: { email: 'new@example.com' } };
      const req = mockRequest(signUpDetails);
      const res = mockResponse();
      const signUpResult = { userSub: 'uuid-123', userConfirmed: false };
      mockAuthService.signUp.mockResolvedValue(signUpResult);

      await controller.signUp(req, res, mockNext);

      expect(mockAuthService.signUp).toHaveBeenCalledWith(signUpDetails);
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(signUpResult);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should call next with error on signup failure', async () => {
      const signUpDetails = { username: 'existinguser', password: 'password123', attributes: { email: 'new@example.com' } };
      const req = mockRequest(signUpDetails);
      const res = mockResponse();
      const error = new ValidationError('Username already exists.');
      mockAuthService.signUp.mockRejectedValue(error);

      await controller.signUp(req, res, mockNext);

      expect(mockAuthService.signUp).toHaveBeenCalledWith(signUpDetails);
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });

  describe('confirmSignUp', () => {
    it('should return 200 on successful confirmation', async () => {
      const req = mockRequest({ username: 'user', confirmationCode: '123456' });
      const res = mockResponse();
      mockAuthService.confirmSignUp.mockResolvedValue(undefined);

      await controller.confirmSignUp(req, res, mockNext);

      expect(mockAuthService.confirmSignUp).toHaveBeenCalledWith('user', '123456');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ message: 'Account confirmed successfully.' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should call next with error on confirmation failure', async () => {
      const req = mockRequest({ username: 'user', confirmationCode: 'wrongcode' });
      const res = mockResponse();
      const error = new AuthenticationError('Invalid confirmation code.');
      mockAuthService.confirmSignUp.mockRejectedValue(error);

      await controller.confirmSignUp(req, res, mockNext);

      expect(mockAuthService.confirmSignUp).toHaveBeenCalledWith('user', 'wrongcode');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });

  describe('logout', () => {
    it('should return 204 on successful logout', async () => {
      const req = mockRequest({}, { authorization: 'Bearer valid_token' });
      const res = mockResponse();
      mockAuthService.logout.mockResolvedValue(undefined);

      await controller.logout(req, res, mockNext);

      expect(mockAuthService.logout).toHaveBeenCalledWith('valid_token');
      expect(res.status).toHaveBeenCalledWith(204);
      expect(res.send).toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should call next with AuthenticationError if auth header is missing', async () => {
      const req = mockRequest({}, {});
      const res = mockResponse();

      await controller.logout(req, res, mockNext);

      expect(mockAuthService.logout).not.toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
      expect(res.send).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ message: 'Authorization header missing or invalid' }));
    });

    it('should call next with error on logout failure', async () => {
      const req = mockRequest({}, { authorization: 'Bearer invalid_token' });
      const res = mockResponse();
      const error = new AuthenticationError('Token is invalid.');
      mockAuthService.logout.mockRejectedValue(error);

      await controller.logout(req, res, mockNext);

      expect(mockAuthService.logout).toHaveBeenCalledWith('invalid_token');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.send).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });

  describe('forgotPassword', () => {
    it('should return 200 with message on success', async () => {
      const req = mockRequest({ username: 'user' });
      const res = mockResponse();
      mockAuthService.initiateForgotPassword.mockResolvedValue({ Destination: 'a***@b.com', DeliveryMedium: 'EMAIL' });

      await controller.forgotPassword(req, res, mockNext);

      expect(mockAuthService.initiateForgotPassword).toHaveBeenCalledWith('user');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ message: expect.stringContaining('password reset code has been sent') });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 200 with generic message even on internal service error', async () => {
      const req = mockRequest({ username: 'user' });
      const res = mockResponse();
      const error = new Error('Internal Cognito Error');
      mockAuthService.initiateForgotPassword.mockRejectedValue(error);

      await controller.forgotPassword(req, res, mockNext);

      expect(mockAuthService.initiateForgotPassword).toHaveBeenCalledWith('user');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ message: expect.stringContaining('password reset code has been sent') });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should call next with error for specific operational errors', async () => {
      const req = mockRequest({ username: 'user' });
      const res = mockResponse();
      const error = new Error('Rate limit exceeded');
      error.name = 'RateLimitError';
      mockAuthService.initiateForgotPassword.mockRejectedValue(error);

      await controller.forgotPassword(req, res, mockNext);

      expect(mockAuthService.initiateForgotPassword).toHaveBeenCalledWith('user');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });

  describe('resetPassword', () => {
    it('should return 200 on successful password reset', async () => {
      const req = mockRequest({ username: 'user', confirmationCode: 'code123', newPassword: 'newPassword123!' });
      const res = mockResponse();
      mockAuthService.confirmForgotPassword.mockResolvedValue(undefined);

      await controller.resetPassword(req, res, mockNext);

      expect(mockAuthService.confirmForgotPassword).toHaveBeenCalledWith('user', 'code123', 'newPassword123!');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ message: 'Password has been reset successfully.' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should call next with error on reset failure', async () => {
      const req = mockRequest({ username: 'user', confirmationCode: 'wrongcode', newPassword: 'newPassword123!' });
      const res = mockResponse();
      const error = new AuthenticationError('Invalid code or password policy violation.');
      mockAuthService.confirmForgotPassword.mockRejectedValue(error);

      await controller.resetPassword(req, res, mockNext);

      expect(mockAuthService.confirmForgotPassword).toHaveBeenCalledWith('user', 'wrongcode', 'newPassword123!');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });

  describe('changePassword', () => {
    it('should return 200 on successful password change', async () => {
      const req = mockRequest({ oldPassword: 'oldPassword', newPassword: 'newPassword123!' }, { authorization: 'Bearer valid_token' });
      const res = mockResponse();
      mockAuthService.changePassword.mockResolvedValue(undefined);

      await controller.changePassword(req, res, mockNext);

      expect(mockAuthService.changePassword).toHaveBeenCalledWith('valid_token', 'oldPassword', 'newPassword123!');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ message: 'Password changed successfully.' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should call next with AuthenticationError if auth header is missing', async () => {
      const req = mockRequest({ oldPassword: 'oldPassword', newPassword: 'newPassword123!' }, {});
      const res = mockResponse();

      await controller.changePassword(req, res, mockNext);

      expect(mockAuthService.changePassword).not.toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ message: 'Authorization header missing or invalid' }));
    });

    it('should call next with error on change password failure', async () => {
      const req = mockRequest({ oldPassword: 'wrongOldPassword', newPassword: 'newPassword123!' }, { authorization: 'Bearer valid_token' });
      const res = mockResponse();
      const error = new AuthenticationError('Incorrect old password.');
      mockAuthService.changePassword.mockRejectedValue(error);

      await controller.changePassword(req, res, mockNext);

      expect(mockAuthService.changePassword).toHaveBeenCalledWith('valid_token', 'wrongOldPassword', 'newPassword123!');
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(error);
    });
  });
});