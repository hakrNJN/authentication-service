"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const supertest_1 = __importDefault(require("supertest"));
const auth_controller_1 = require("../../src/api/controllers/auth.controller");
const dtos_1 = require("../../src/api/dtos");
const error_middleware_1 = require("../../src/api/middlewares/error.middleware");
const validation_middleware_1 = require("../../src/api/middlewares/validation.middleware");
const container_1 = require("../../src/container");
const domain_1 = require("../../src/domain");
const types_1 = require("../../src/shared/constants/types");
const mockAuthService_1 = require("../mocks/mockAuthService");
const mockConfigService_1 = require("../mocks/mockConfigService");
const mockLogger_1 = require("../mocks/mockLogger");
jest.mock('../mocks/mockAuthService');
// Setup test application with error handling
const app = (0, express_1.default)();
app.use(express_1.default.json());
// Mock DI setup
beforeEach(() => {
    // Clear container and reset mocks before each test
    container_1.container.clearInstances();
    jest.clearAllMocks();
    // Register mocks in container
    container_1.container.registerInstance(types_1.TYPES.Logger, mockLogger_1.mockLogger);
    container_1.container.registerInstance(types_1.TYPES.ConfigService, mockConfigService_1.mockConfigService);
    container_1.container.registerInstance(types_1.TYPES.AuthService, mockAuthService_1.mockAuthService);
    // Create controller instance
    const authController = new auth_controller_1.AuthController(mockAuthService_1.mockAuthService, mockLogger_1.mockLogger);
    // Set up routes manually instead of importing auth.routes
    const router = express_1.default.Router();
    router.post('/login', (0, validation_middleware_1.validationMiddleware)(dtos_1.LoginSchema, mockLogger_1.mockLogger), authController.login.bind(authController));
    router.post('/verify-mfa', authController.verifyMfa.bind(authController));
    router.post('/refresh-token', authController.refresh.bind(authController));
    router.post('/signup', authController.signUp.bind(authController));
    router.post('/confirm-signup', authController.confirmSignUp.bind(authController));
    router.post('/logout', authController.signOut.bind(authController));
    router.post('/forgot-password', authController.forgotPassword.bind(authController));
    router.post('/reset-password', authController.resetPassword.bind(authController));
    router.post('/change-password', authController.changePassword.bind(authController));
    // Mount routes and error middleware
    app.use('/auth', router);
    app.use((0, error_middleware_1.createErrorMiddleware)(mockLogger_1.mockLogger, mockConfigService_1.mockConfigService));
});
describe('Auth Routes Integration Tests', () => {
    describe('POST /auth/login', () => {
        it('should return 200 and tokens on successful login', async () => {
            const loginData = { username: 'testuser', password: 'password123' };
            const tokens = { accessToken: 'at', refreshToken: 'rt', expiresIn: 3600, tokenType: 'Bearer' };
            mockAuthService_1.mockAuthService.login.mockResolvedValue(tokens);
            const response = await (0, supertest_1.default)(app)
                .post('/auth/login')
                .send(loginData);
            expect(response.status).toBe(200);
            expect(response.body).toEqual(tokens);
            expect(mockAuthService_1.mockAuthService.login).toHaveBeenCalledWith(loginData.username, loginData.password);
        });
        it('should return 400 if username is missing', async () => {
            const response = await (0, supertest_1.default)(app)
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
            const response = await (0, supertest_1.default)(app)
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
            mockAuthService_1.mockAuthService.login.mockRejectedValue(new domain_1.InvalidCredentialsError('Invalid credentials'));
            const response = await (0, supertest_1.default)(app)
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
