import { Request, Response, NextFunction } from 'express';
import { IAuthService } from '../../../../src/application/interfaces/IAuthService';
import { ILogger } from '../../../../src/application/interfaces/ILogger';
import { AuthenticationError } from '../../../../src/domain/exceptions/AuthenticationError';

// Mock the container and middleware
const mockContainer = {
  resolve: jest.fn()
};

jest.mock('../../../../src/container', () => ({
  container: mockContainer
}));

// Import after mocking
import { authGuardMiddleware } from '../../../../src/api/middlewares/auth.guard.middleware';

describe('AuthGuardMiddleware', () => {
  let mockAuthService: jest.Mocked<IAuthService>;
  let mockLogger: jest.Mocked<ILogger>;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: jest.MockedFunction<NextFunction>;

  beforeEach(() => {
    jest.clearAllMocks();

    mockAuthService = {
      getUserInfo: jest.fn(),
      login: jest.fn(),
      signUp: jest.fn(),
      confirmSignUp: jest.fn(),
      verifyMfa: jest.fn(),
      refresh: jest.fn(),
      signOut: jest.fn(),
      initiateForgotPassword: jest.fn(),
      confirmForgotPassword: jest.fn(),
      changePassword: jest.fn()
    } as jest.Mocked<IAuthService>;

    mockLogger = {
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn()
    } as jest.Mocked<ILogger>;

    // Mock container resolve to return appropriate services
    mockContainer.resolve.mockImplementation((type: symbol) => {
      if (type === Symbol.for('AuthService')) return mockAuthService;
      if (type === Symbol.for('Logger')) return mockLogger;
      throw new Error(`Unknown service type: ${type.toString()}`);
    });

    mockRequest = {
      headers: {}
    };

    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis()
    };

    mockNext = jest.fn();
  });

  describe('Authorization Header Validation', () => {
    it('should reject request without authorization header', async () => {
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Authorization header missing or invalid'
      }));
    });

    it('should reject request with empty authorization header', async () => {
      mockRequest.headers = { authorization: '' };
      
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });

    it('should reject request with malformed authorization header', async () => {
      mockRequest.headers = { authorization: 'InvalidFormat' };
      
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });

    it('should reject request with non-Bearer token', async () => {
      mockRequest.headers = { authorization: 'Basic dGVzdDp0ZXN0' };
      
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });

    it('should reject Bearer token without actual token', async () => {
      mockRequest.headers = { authorization: 'Bearer' };
      
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });

    it('should reject Bearer token with only whitespace', async () => {
      mockRequest.headers = { authorization: 'Bearer   ' };
      
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });
  });

  describe('Token Validation', () => {
    it('should successfully validate valid token and call next', async () => {
      mockRequest.headers = { authorization: 'Bearer valid-access-token' };
      mockAuthService.getUserInfo.mockResolvedValue({
        username: 'testuser',
        userSub: 'user-123',
        attributes: { email: 'test@example.com' }
      });

      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockAuthService.getUserInfo).toHaveBeenCalledWith('valid-access-token');
      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should attach user info to request object', async () => {
      const userInfo = {
        username: 'testuser',
        userSub: 'user-123',
        attributes: { email: 'test@example.com', name: 'Test User' }
      };

      mockRequest.headers = { authorization: 'Bearer valid-access-token' };
      mockAuthService.getUserInfo.mockResolvedValue(userInfo);

      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect((mockRequest as any).user).toEqual(userInfo);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle invalid token from auth service', async () => {
      mockRequest.headers = { authorization: 'Bearer invalid-token' };
      mockAuthService.getUserInfo.mockRejectedValue(new Error('Invalid token'));

      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockLogger.error).toHaveBeenCalledWith('Authentication failed in authGuardMiddleware', { error: expect.any(Error) });
      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Invalid token'
      }));
    });

    it('should handle expired token from auth service', async () => {
      mockRequest.headers = { authorization: 'Bearer expired-token' };
      mockAuthService.getUserInfo.mockRejectedValue(new Error('Token has expired'));

      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockLogger.error).toHaveBeenCalledWith('Authentication failed in authGuardMiddleware', { error: expect.any(Error) });
      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });

    it('should handle blacklisted token from auth service', async () => {
      mockRequest.headers = { authorization: 'Bearer blacklisted-token' };
      mockAuthService.getUserInfo.mockRejectedValue(new Error('Token has been invalidated'));

      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockLogger.error).toHaveBeenCalledWith('Authentication failed in authGuardMiddleware', { error: expect.any(Error) });
      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });
  });

  describe('Case Sensitivity Tests', () => {
    it('should handle lowercase bearer token', async () => {
      mockRequest.headers = { authorization: 'bearer valid-access-token' };
      
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });

    it('should handle mixed case bearer token', async () => {
      mockRequest.headers = { authorization: 'BeArEr valid-access-token' };
      
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });

    it('should handle uppercase authorization header name', async () => {
      mockRequest.headers = { AUTHORIZATION: 'Bearer valid-access-token' };
      
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });
  });

  describe('Token Format Edge Cases', () => {
    it('should handle tokens with special characters', async () => {
      mockRequest.headers = { authorization: 'Bearer token-with-dashes_and_underscores.and.dots' };
      mockAuthService.getUserInfo.mockResolvedValue({
        username: 'testuser',
        userSub: 'user-123',
        attributes: {}
      });

      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockAuthService.getUserInfo).toHaveBeenCalledWith('token-with-dashes_and_underscores.and.dots');
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle very long tokens', async () => {
      const longToken = 'a'.repeat(5000);
      mockRequest.headers = { authorization: `Bearer ${longToken}` };
      mockAuthService.getUserInfo.mockResolvedValue({
        username: 'testuser',
        userSub: 'user-123',
        attributes: {}
      });

      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockAuthService.getUserInfo).toHaveBeenCalledWith(longToken);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject tokens with multiple spaces after Bearer', async () => {
      mockRequest.headers = { authorization: 'Bearer    valid-token-with-spaces' };

      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      // Should reject due to empty token after split (multiple spaces result in empty string at index 1)
      expect(mockAuthService.getUserInfo).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(expect.any(AuthenticationError));
    });
  });

  describe('Error Response Format', () => {
    it('should return consistent error response format', async () => {
      mockRequest.headers = {};
      
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Authorization header missing or invalid'
      }));
    });

    it('should not expose internal error details', async () => {
      mockRequest.headers = { authorization: 'Bearer invalid-token' };
      mockAuthService.getUserInfo.mockRejectedValue(new Error('Internal database connection failed'));

      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Invalid token'
      }));
    });
  });

  describe('Dependency Injection', () => {
    it('should resolve auth service from container', async () => {
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      mockAuthService.getUserInfo.mockResolvedValue({
        username: 'testuser',
        userSub: 'user-123',
        attributes: {}
      });
      
      const middleware = authGuardMiddleware();
      
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockContainer.resolve).toHaveBeenCalledWith(Symbol.for('AuthService'));
    });

    it('should handle container resolution errors', async () => {
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      mockContainer.resolve.mockImplementation(() => {
        throw new Error('Container resolution failed');
      });

      expect(() => authGuardMiddleware()).toThrow('Container resolution failed');
    });
  });
});