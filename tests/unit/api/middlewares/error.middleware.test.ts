import { Request, Response } from 'express';
import { createErrorMiddleware } from '../../../../src/api/middlewares/error.middleware';
import { IConfigService } from '../../../../src/application/interfaces/IConfigService';
import { ValidationError } from '../../../../src/domain';
import { BaseError } from '../../../../src/shared/errors/BaseError';
import { mockLogger } from '../../../mocks/mockLogger';

// Create mock config service
const mockConfig: jest.Mocked<IConfigService> = {
    get: jest.fn(),
    getNumber: jest.fn(),
    getBoolean: jest.fn(),
    getAllConfig: jest.fn(),
    has: jest.fn(),
};

// Define error middleware test
describe('Error Middleware', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let nextFunction: jest.Mock;

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
        mockConfig.get.mockImplementation((key: string) => {
            if (key === 'NODE_ENV') return 'development';
            return undefined;
        });
    });

    describe('Development Environment', () => {
        it('should handle ValidationError with proper status code and details', () => {
            const error = new ValidationError('Invalid input');
            const errorMiddleware = createErrorMiddleware(mockLogger, mockConfig);
            
            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith('Invalid input', error);
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
            const errorMiddleware = createErrorMiddleware(mockLogger, mockConfig);
            
            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith('Error processing request GET /test: Error', error);
            expect(mockResponse.status).toHaveBeenCalledWith(500);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'Error',
                message: 'Detailed internal error message',
                stack: expect.any(String)
            });
        });

        it('should handle BaseError with custom status code', () => {
            class CustomOperationalError extends BaseError {
                constructor() {
                    super('CustomOperationalError', 422, 'Custom validation failed');
                }
            }
            const error = new CustomOperationalError();
            const errorMiddleware = createErrorMiddleware(mockLogger, mockConfig);
            
            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith('Custom validation failed', error);
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
            mockConfig.get.mockImplementation((key: string) => {
                if (key === 'NODE_ENV') return 'production';
                return undefined;
            });
        });

        it('should sanitize unknown error messages and name, and omit stack', () => {
            const error = new Error('Detailed internal database connection failure');
            const errorMiddleware = createErrorMiddleware(mockLogger, mockConfig);
            
            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith('Error processing request GET /test: Error', error);
            expect(mockResponse.status).toHaveBeenCalledWith(500);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'InternalServerError',
                message: 'An unexpected error occurred'
            });
            expect(mockResponse.json).not.toHaveBeenCalledWith(
                expect.objectContaining({
                    stack: expect.any(String)
                })
            );
        });

        it('should still expose validation error details in production', () => {
            const error = new ValidationError('Invalid input data');
            const errorMiddleware = createErrorMiddleware(mockLogger, mockConfig);
            
            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

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
            const errorMiddleware = createErrorMiddleware(mockLogger, mockConfig);
            
            errorMiddleware(errorString, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith('Error processing request GET /test: Error', expect.any(Error));
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
            const errorMiddleware = createErrorMiddleware(mockLogger, mockConfig);
            
            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.warn).toHaveBeenCalledWith(
                'Error occurred after headers were sent, delegating to default handler.',
                expect.objectContaining({
                    errorName: 'Error',
                    path: '/test'
                })
            );
            expect(mockResponse.status).not.toHaveBeenCalled();
            expect(mockResponse.json).not.toHaveBeenCalled();
            expect(nextFunction).toHaveBeenCalledWith(error);
        });
    });
});