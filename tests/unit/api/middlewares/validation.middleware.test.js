"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const zod_1 = require("zod");
const validation_middleware_1 = require("../../../../src/api/middlewares/validation.middleware");
const domain_1 = require("../../../../src/domain");
const mockLogger_1 = require("../../../mocks/mockLogger");
describe('Validation Middleware', () => {
    let mockRequest;
    let mockResponse;
    let nextFunction;
    beforeEach(() => {
        mockRequest = {
            body: {}
        };
        mockResponse = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis()
        };
        nextFunction = jest.fn();
        jest.clearAllMocks();
    });
    const TestSchema = zod_1.z.object({
        username: zod_1.z.string().min(3),
        email: zod_1.z.string().email(),
        age: zod_1.z.number().min(18).optional()
    });
    it('should pass validation for valid data', async () => {
        mockRequest.body = {
            username: 'testuser',
            email: 'test@example.com',
            age: 25
        };
        const middleware = (0, validation_middleware_1.validationMiddleware)(TestSchema, mockLogger_1.mockLogger);
        await middleware(mockRequest, mockResponse, nextFunction);
        expect(nextFunction).toHaveBeenCalledWith();
        expect(mockLogger_1.mockLogger.debug).toHaveBeenCalledWith('Request validation successful');
    });
    it('should handle validation error for missing required fields', async () => {
        mockRequest.body = {
            username: 'testuser'
            // missing email field
        };
        const middleware = (0, validation_middleware_1.validationMiddleware)(TestSchema, mockLogger_1.mockLogger);
        await middleware(mockRequest, mockResponse, nextFunction);
        expect(nextFunction).toHaveBeenCalledWith(expect.any(domain_1.ValidationError));
        expect(mockLogger_1.mockLogger.warn).toHaveBeenCalledWith('Request validation failed:', expect.any(Object));
    });
    it('should handle validation error for invalid email format', async () => {
        mockRequest.body = {
            username: 'testuser',
            email: 'invalid-email'
        };
        const middleware = (0, validation_middleware_1.validationMiddleware)(TestSchema, mockLogger_1.mockLogger);
        await middleware(mockRequest, mockResponse, nextFunction);
        expect(nextFunction).toHaveBeenCalledWith(expect.any(domain_1.ValidationError));
        expect(mockLogger_1.mockLogger.warn).toHaveBeenCalledWith('Request validation failed:', expect.any(Object));
    });
    it('should handle validation error for invalid username length', async () => {
        mockRequest.body = {
            username: 'ab', // too short
            email: 'test@example.com'
        };
        const middleware = (0, validation_middleware_1.validationMiddleware)(TestSchema, mockLogger_1.mockLogger);
        await middleware(mockRequest, mockResponse, nextFunction);
        expect(nextFunction).toHaveBeenCalledWith(expect.any(domain_1.ValidationError));
        expect(mockLogger_1.mockLogger.warn).toHaveBeenCalledWith('Request validation failed:', expect.any(Object));
    });
    it('should pass validation when optional field is omitted', async () => {
        mockRequest.body = {
            username: 'testuser',
            email: 'test@example.com'
            // age is optional
        };
        const middleware = (0, validation_middleware_1.validationMiddleware)(TestSchema, mockLogger_1.mockLogger);
        await middleware(mockRequest, mockResponse, nextFunction);
        expect(nextFunction).toHaveBeenCalledWith();
        expect(mockLogger_1.mockLogger.debug).toHaveBeenCalledWith('Request validation successful');
    });
    it('should handle validation error for invalid optional field value', async () => {
        mockRequest.body = {
            username: 'testuser',
            email: 'test@example.com',
            age: 17 // below minimum age
        };
        const middleware = (0, validation_middleware_1.validationMiddleware)(TestSchema, mockLogger_1.mockLogger);
        await middleware(mockRequest, mockResponse, nextFunction);
        expect(nextFunction).toHaveBeenCalledWith(expect.any(domain_1.ValidationError));
        expect(mockLogger_1.mockLogger.warn).toHaveBeenCalledWith('Request validation failed:', expect.any(Object));
    });
    it('should include all validation errors in the error message', async () => {
        mockRequest.body = {
            username: 'ab', // too short
            email: 'invalid-email', // invalid format
            age: 17 // below minimum
        };
        const middleware = (0, validation_middleware_1.validationMiddleware)(TestSchema, mockLogger_1.mockLogger);
        await middleware(mockRequest, mockResponse, nextFunction);
        const error = nextFunction.mock.calls[0][0];
        expect(error).toBeInstanceOf(domain_1.ValidationError);
        expect(error.message).toContain('String must contain at least 3 character(s)');
        expect(error.message).toContain('Invalid email');
        expect(error.message).toContain('Number must be greater than or equal to 18');
    });
});
