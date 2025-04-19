import express from 'express';
import request from 'supertest';
import { AuthController } from '../../src/api/controllers/auth.controller';
import { LoginSchema } from '../../src/api/dtos';
import { createErrorMiddleware } from '../../src/api/middlewares/error.middleware';
import { validationMiddleware } from '../../src/api/middlewares/validation.middleware';
import { IAuthService } from '../../src/application/interfaces/IAuthService';
import { IConfigService } from '../../src/application/interfaces/IConfigService';
import { ILogger } from '../../src/application/interfaces/ILogger';
import { container } from '../../src/container';
import { InvalidCredentialsError } from '../../src/domain';
import { TYPES } from '../../src/shared/constants/types';
import { mockAuthService } from '../mocks/mockAuthService';
import { mockConfigService } from '../mocks/mockConfigService';
import { mockLogger } from '../mocks/mockLogger';

// Setup test application with error handling
const app = express();
app.use(express.json());

// Mock DI setup
beforeEach(() => {
    // Clear container and reset mocks before each test
    container.clearInstances();
    jest.clearAllMocks();

    // Register mocks in container
    container.registerInstance<ILogger>(TYPES.Logger, mockLogger);
    container.registerInstance<IConfigService>(TYPES.ConfigService, mockConfigService);
    container.registerInstance<IAuthService>(TYPES.AuthService, mockAuthService);

    // Create controller instance
    const authController = new AuthController(mockAuthService);

    // Set up routes manually instead of importing auth.routes
    const router = express.Router();
    router.post('/login', 
        validationMiddleware(LoginSchema,mockLogger),
        authController.login.bind(authController)
    );
    router.post('/verify-mfa', authController.verifyMfa.bind(authController));
    router.post('/refresh-token', authController.refresh.bind(authController));
    router.post('/signup', authController.signUp.bind(authController));
    router.post('/confirm-signup', authController.confirmSignUp.bind(authController));
    router.post('/logout', authController.logout.bind(authController));
    router.post('/forgot-password', authController.forgotPassword.bind(authController));
    router.post('/reset-password', authController.resetPassword.bind(authController));
    router.post('/change-password', authController.changePassword.bind(authController));

    // Mount routes and error middleware
    app.use('/auth', router);
    app.use(createErrorMiddleware(mockLogger, mockConfigService));
});

describe('Auth Routes Integration Tests', () => {
    describe('POST /auth/login', () => {
        it('should return 200 and tokens on successful login', async () => {
            const loginData = { username: 'testuser', password: 'password123' };
            const tokens = { accessToken: 'at', refreshToken: 'rt', expiresIn: 3600, tokenType: 'Bearer' };
            mockAuthService.login.mockResolvedValue(tokens);

            const response = await request(app)
                .post('/auth/login')
                .send(loginData);

            expect(response.status).toBe(200);
            expect(response.body).toEqual(tokens);
            expect(mockAuthService.login).toHaveBeenCalledWith(loginData.username, loginData.password);
        });

        it('should return 400 if username is missing', async () => {
            const response = await request(app)
                .post('/auth/login')
                .send({ password: 'password123' });

            expect(response.status).toBe(400);
            expect(response.body).toEqual(expect.objectContaining({
                name: 'ValidationError',
                message: expect.any(String),
                status: 'error'
            }));
        });

        it('should return 400 if password is missing', async () => {
            const response = await request(app)
                .post('/auth/login')
                .send({ username: 'testuser' });

            expect(response.status).toBe(400);
            expect(response.body).toEqual(expect.objectContaining({
                name: 'ValidationError',
                message: expect.any(String),
                status: 'error'
            }));
        });

        it('should return 401 on invalid credentials', async () => {
            const loginData = { username: 'testuser', password: 'wrongpass' };
            mockAuthService.login.mockRejectedValue(new InvalidCredentialsError('Invalid credentials'));

            const response = await request(app)
                .post('/auth/login')
                .send(loginData);

            expect(response.status).toBe(401);
            expect(response.body).toEqual(expect.objectContaining({
                name: 'InvalidCredentialsError',
                message: expect.any(String),
                status: 'error'
            }));
        });
    });
});