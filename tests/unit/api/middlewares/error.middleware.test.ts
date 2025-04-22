import { NextFunction, Request, Response } from 'express'; // Added NextFunction import
import { createErrorMiddleware } from '../../../../src/api/middlewares/error.middleware';
// Assuming these domain errors extend BaseError or are handled appropriately
import { IConfigService } from '../../../../src/application/interfaces/IConfigService'; // Use interfaces for mocks
import { ILogger } from '../../../../src/application/interfaces/ILogger'; // Use interfaces for mocks
import { AuthenticationError } from '../../../../src/domain/exceptions/AuthenticationError'; // Example: Added NotFoundError
import { BaseError, NotFoundError, ValidationError } from '../../../../src/shared/errors/BaseError';

// Mock implementations conforming to interfaces
const mockLogger: jest.Mocked<ILogger> = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
};

const mockConfigService: jest.Mocked<IConfigService> = {
    get: jest.fn(),
    getNumber: jest.fn(),
    getBoolean: jest.fn(),
    getAllConfig: jest.fn(),
    has: jest.fn(),
    // Ensure all methods from IConfigService are mocked if needed elsewhere,
    // or use jest.createMockFromModule if appropriate for more complex interfaces.
};


describe('Error Middleware', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let nextFunction: jest.Mock<NextFunction>; // More specific type
    let errorMiddleware: (err: Error, req: Request, res: Response, next: NextFunction) => void; // Define type for middleware instance

    // Helper to reset mocks and setup NODE_ENV
    const setupEnvironment = (nodeEnv: 'development' | 'production') => {
        jest.clearAllMocks(); // Clear mocks before each test run

        mockRequest = { // Reset request object
            method: 'GET',
            originalUrl: '/test'
        };
        mockResponse = { // Reset response object
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            headersSent: false
        };
        nextFunction = jest.fn(); // Reset next function mock

        // Mock configService.get based on environment
        mockConfigService.get.mockImplementation((key: string, defaultValue?: any) => {
            if (key === 'NODE_ENV') return nodeEnv;
            return defaultValue; // Return default value if provided
        });

        // Recreate middleware instance with potentially updated mock behavior
        errorMiddleware = createErrorMiddleware(mockLogger, mockConfigService);
    };


    describe('Development Environment', () => {
        beforeEach(() => {
            setupEnvironment('development');
        });

        it('should handle ValidationError with 400, details, and stack', () => {
            const errorDetails = { field: 'email', message: 'Invalid format' };
            // Assuming ValidationError extends BaseError and might have a details property
            const error = new ValidationError('Invalid input', errorDetails); // Pass details if applicable

            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Error processing request GET /test: Invalid input'), error);
            expect(mockResponse.status).toHaveBeenCalledWith(400); // Default for ValidationError
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'ValidationError',
                message: 'Invalid input',
                details: errorDetails, // Check for details if your error class provides them
                stack: expect.any(String)
            });
            expect(nextFunction).not.toHaveBeenCalled();
        });

        it('should handle AuthenticationError with 401 and stack', () => {
            const error = new AuthenticationError('Invalid credentials'); // Assumes extends BaseError

            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Invalid credentials'), error);
            expect(mockResponse.status).toHaveBeenCalledWith(401);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'AuthenticationError',
                message: 'Invalid credentials',
                stack: expect.any(String)
            });
            expect(nextFunction).not.toHaveBeenCalled();
        });

        // --- CORRECTED TEST ---
        it('should handle unknown/programmer errors with 500 and include actual error details and stack', () => {
            const error = new Error('Detailed internal error message'); // Standard JS Error

            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Detailed internal error message'), error);
            expect(mockResponse.status).toHaveBeenCalledWith(500);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'Error', // Should be the actual error name in dev
                message: 'Detailed internal error message', // Should be the actual error message in dev
                stack: expect.any(String) // Should include stack in dev
            });
            expect(nextFunction).not.toHaveBeenCalled();
        });
        // --- END CORRECTION ---

        it('should handle BaseError with custom status code and stack', () => {
            // Assuming BaseError constructor: message, statusCode, isOperational, details?
            // Let's refine BaseError usage if possible
            class CustomOperationalError extends BaseError {
                constructor(message: string) {
                    super(message, 422, 'CustomOperationalError',true); // message, statusCode, isOperational, name
                }
            }
            const error = new CustomOperationalError('Custom validation failed');

            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Custom validation failed'), error);
            expect(mockResponse.status).toHaveBeenCalledWith(422); // Custom status code
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'CustomOperationalError', // Use the specific name
                message: 'Custom validation failed',
                stack: expect.any(String)
            });
            expect(nextFunction).not.toHaveBeenCalled();
        });
    });

    describe('Production Environment', () => {
        beforeEach(() => {
            setupEnvironment('production');
        });

        it('should handle operational errors (e.g., ValidationError) without stack or details', () => {
            const errorDetails = { field: 'email', message: 'Invalid format' };
            const error = new ValidationError('Invalid input', errorDetails);

            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Invalid input'), error);
            expect(mockResponse.status).toHaveBeenCalledWith(400);
            // Check response does NOT contain sensitive info
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'ValidationError',
                message: 'Invalid input' // No stack, no details
            });
            // Explicitly check sensitive fields are absent
            expect(mockResponse.json).not.toHaveBeenCalledWith(
                expect.objectContaining({ stack: expect.anything() })
            );
            expect(mockResponse.json).not.toHaveBeenCalledWith(
                expect.objectContaining({ details: expect.anything() })
            );
            expect(nextFunction).not.toHaveBeenCalled();
        });

        it('should sanitize unknown/programmer error messages and name, and omit stack', () => {
            const error = new Error('Detailed internal database connection failure');

            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('database connection failure'), error);
            expect(mockResponse.status).toHaveBeenCalledWith(500);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'InternalServerError', // Generic name
                message: 'An unexpected internal server error occurred.' // Generic message
                // No stack
            });
            // Explicitly check stack is absent
            expect(mockResponse.json).not.toHaveBeenCalledWith(
                expect.objectContaining({ stack: expect.anything() })
            );
            expect(nextFunction).not.toHaveBeenCalled();
        });
    });

    describe('Edge Cases', () => {
        // No need to call setupEnvironment if NODE_ENV doesn't matter for the test,
        // but it's good practice to ensure mocks are reset. Let's keep using it.
        beforeEach(() => {
            setupEnvironment('development'); // Default to dev for edge cases unless prod logic differs
        });

        it('should handle non-Error objects thrown (e.g., string) gracefully', () => {
            // In JS/TS you shouldn't really throw non-Errors, but middleware should cope
            const errorString = 'Something bad happened as a string';

            // Cast to 'any' because middleware expects Error type hint, but JS allows throwing anything
            errorMiddleware(errorString as any, mockRequest as Request, mockResponse as Response, nextFunction);

            // Logger might behave differently, check it handles non-errors
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Something bad happened as a string'), errorString);
            expect(mockResponse.status).toHaveBeenCalledWith(500);
            // In dev, it should try to use the string as message, name might be undefined or generic
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'Error', // The middleware's default if name isn't available on the thrown object
                message: 'Something bad happened as a string', // It uses the string itself
                stack: undefined // Non-errors don't have stacks
            });
            expect(nextFunction).not.toHaveBeenCalled();
        });

        // --- CORRECTED TEST ---
        it('should log warning, not send response, and call next() if headers already sent', () => {
            mockResponse.headersSent = true;
            const error = new NotFoundError('Resource not found after headers sent');

            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            // Check the specific warning log message
            expect(mockLogger.warn).toHaveBeenCalledWith(
                'Error occurred after headers were sent, delegating to default handler.',
                { errorName: error.name, path: mockRequest.originalUrl } // Ensure path matches if provided
            );
            expect(mockLogger.error).not.toHaveBeenCalled(); // Should NOT call logger.error
            expect(mockResponse.status).not.toHaveBeenCalled(); // Should NOT set status
            expect(mockResponse.json).not.toHaveBeenCalled(); // Should NOT send JSON body
            expect(nextFunction).toHaveBeenCalledTimes(1); // Should delegate
            expect(nextFunction).toHaveBeenCalledWith(error); // Should delegate with the original error
        });
        // --- END CORRECTION ---

        it('should handle errors without stack traces gracefully (dev)', () => {
            setupEnvironment('development'); // Ensure dev environment for this check
            const error = new AuthenticationError('No stack available');
            delete error.stack; // Remove stack property

            errorMiddleware(error, mockRequest as Request, mockResponse as Response, nextFunction);

            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('No stack available'), error);
            expect(mockResponse.status).toHaveBeenCalledWith(401);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'error',
                name: 'AuthenticationError',
                message: 'No stack available'
                // stack property should be absent
            });
            // Explicitly check stack is absent
            expect(mockResponse.json).not.toHaveBeenCalledWith(
                expect.objectContaining({ stack: expect.anything() })
            );
            expect(nextFunction).not.toHaveBeenCalled();
        });
    });
});