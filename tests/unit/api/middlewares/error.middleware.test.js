"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const error_middleware_1 = require("../../../../src/api/middlewares/error.middleware");
const domain_1 = require("../../../../src/domain");
const BaseError_1 = require("../../../../src/shared/errors/BaseError");
const mockLogger_1 = require("../../../mocks/mockLogger");
// Create mock config service
const mockConfig = {
    get: jest.fn(),
    getNumber: jest.fn(),
    getBoolean: jest.fn(),
    getAllConfig: jest.fn(),
    has: jest.fn(),
    getOrThrow: jest.fn(),
};
// Define error middleware test
describe('Error Middleware', () => {
    let mockRequest;
    let mockResponse;
    let nextFunction;
    beforeEach(() => {
        mockRequest = {
            method: 'GET',
            originalUrl: '/test'
        };
        mockResponse = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            headersSent: false
        };
        nextFunction = jest.fn();
        jest.clearAllMocks();
        // Set development environment by default
        mockConfig.get.mockImplementation((key) => {
            if (key === 'NODE_ENV')
                return 'development';
            return undefined;
        });
    });
    describe('Development Environment', () => {
        it('should handle ValidationError with proper status code and details', () => {
            const error = new domain_1.ValidationError('Invalid input');
            const errorMiddleware = (0, error_middleware_1.createErrorMiddleware)(mockLogger_1.mockLogger, mockConfig);
            errorMiddleware(error, mockRequest, mockResponse, nextFunction);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith('Invalid input', error);
            expect(mockResponse.status).toHaveBeenCalledWith(400);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'ValidationError',
                message: 'Invalid input',
                stack: expect.any(String)
            });
        });
        it('should handle unknown errors with 500 status code', () => {
            const error = new Error('Detailed internal error message');
            const errorMiddleware = (0, error_middleware_1.createErrorMiddleware)(mockLogger_1.mockLogger, mockConfig);
            errorMiddleware(error, mockRequest, mockResponse, nextFunction);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith('Error processing request GET /test: Error', error);
            expect(mockResponse.status).toHaveBeenCalledWith(500);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'Error',
                message: 'Detailed internal error message',
                stack: expect.any(String)
            });
        });
        it('should handle BaseError with custom status code', () => {
            class CustomOperationalError extends BaseError_1.BaseError {
                constructor() {
                    super('CustomOperationalError', 422, 'Custom validation failed');
                }
            }
            const error = new CustomOperationalError();
            const errorMiddleware = (0, error_middleware_1.createErrorMiddleware)(mockLogger_1.mockLogger, mockConfig);
            errorMiddleware(error, mockRequest, mockResponse, nextFunction);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith('Custom validation failed', error);
            expect(mockResponse.status).toHaveBeenCalledWith(422);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'CustomOperationalError',
                message: 'Custom validation failed',
                stack: expect.any(String)
            });
        });
    });
    describe('Production Environment', () => {
        beforeEach(() => {
            mockConfig.get.mockImplementation((key) => {
                if (key === 'NODE_ENV')
                    return 'production';
                return undefined;
            });
        });
        it('should sanitize unknown error messages and name, and omit stack', () => {
            const error = new Error('Detailed internal database connection failure');
            const errorMiddleware = (0, error_middleware_1.createErrorMiddleware)(mockLogger_1.mockLogger, mockConfig);
            errorMiddleware(error, mockRequest, mockResponse, nextFunction);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith('Error processing request GET /test: Error', error);
            expect(mockResponse.status).toHaveBeenCalledWith(500);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'InternalServerError',
                message: 'An unexpected error occurred'
            });
            expect(mockResponse.json).not.toHaveBeenCalledWith(expect.objectContaining({
                stack: expect.any(String)
            }));
        });
        it('should still expose validation error details in production', () => {
            const error = new domain_1.ValidationError('Invalid input data');
            const errorMiddleware = (0, error_middleware_1.createErrorMiddleware)(mockLogger_1.mockLogger, mockConfig);
            errorMiddleware(error, mockRequest, mockResponse, nextFunction);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'ValidationError',
                message: 'Invalid input data'
            });
        });
    });
    describe('Edge Cases', () => {
        it('should handle non-Error objects thrown (e.g., string) gracefully', () => {
            const errorString = 'Something bad happened as a string';
            const errorMiddleware = (0, error_middleware_1.createErrorMiddleware)(mockLogger_1.mockLogger, mockConfig);
            errorMiddleware(errorString, mockRequest, mockResponse, nextFunction);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith('Error processing request GET /test: Error', expect.any(Error));
            expect(mockResponse.status).toHaveBeenCalledWith(500);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'Error',
                message: errorString,
                stack: expect.any(String)
            });
        });
        it('should log warning and delegate to Express if headers already sent', () => {
            const error = new Error('Test error');
            mockResponse.headersSent = true;
            const errorMiddleware = (0, error_middleware_1.createErrorMiddleware)(mockLogger_1.mockLogger, mockConfig);
            errorMiddleware(error, mockRequest, mockResponse, nextFunction);
            expect(mockLogger_1.mockLogger.warn).toHaveBeenCalledWith('Error occurred after headers were sent, delegating to default handler.', expect.objectContaining({
                errorName: 'Error',
                path: '/test'
            }));
            expect(mockResponse.status).not.toHaveBeenCalled();
            expect(mockResponse.json).not.toHaveBeenCalled();
            expect(nextFunction).toHaveBeenCalledWith(error);
        });
    });
});
