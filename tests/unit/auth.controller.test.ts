import { AuthController } from '../../../src/api/controllers/auth.controller';
import { IAuthService } from '../../../src/application/interfaces/IAuthService';
import { container } from '../../../src/container';
import { AuthenticationError } from '../../../src/domain';
import { TYPES } from '../../../src/shared/constants/types';

describe('AuthController', () => {
  let controller: AuthController;
  let mockAuthService: jest.Mocked<IAuthService>;

  beforeEach(() => {
    mockAuthService = {
      login: jest.fn(),
      refresh: jest.fn(),
      getUserInfo: jest.fn(),
      signUp: jest.fn(),
      confirmSignUp: jest.fn(),
      logout: jest.fn(),
      initiateForgotPassword: jest.fn(),
      confirmForgotPassword: jest.fn(),
      changePassword: jest.fn(),
    } as any;
    container.registerInstance<IAuthService>(TYPES.AuthService, mockAuthService);
    controller = new AuthController(mockAuthService);
  });

  it('login: should return tokens on success', async () => {
    const req: any = { body: { username: 'user', password: 'pass' } };
    const res: any = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    mockAuthService.login.mockResolvedValue({ accessToken: 'token' });
    await controller.login(req, res, jest.fn());
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ accessToken: 'token' });
  });

  it('signUp: should return result on success', async () => {
    const req: any = { body: { username: 'user', password: 'pass', email: 'a@b.com' } };
    const res: any = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    mockAuthService.signUp.mockResolvedValue({ userSub: 'sub' });
    await controller.signUp(req, res, jest.fn());
    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({ userSub: 'sub' });
  });

  it('forgotPassword: should return generic message on error', async () => {
    const req: any = { body: { username: 'user' } };
    const res: any = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    mockAuthService.initiateForgotPassword.mockRejectedValue(new Error('fail'));
    await controller.forgotPassword(req, res, jest.fn());
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ message: expect.any(String) });
  });

  it('getUserInfo: should throw AuthenticationError if no auth header', async () => {
    const req: any = { headers: {} };
    const res: any = {};
    const next = jest.fn();
    await controller.getUserInfo(req, res, next);
    expect(next).toHaveBeenCalledWith(expect.any(AuthenticationError));
  });
});