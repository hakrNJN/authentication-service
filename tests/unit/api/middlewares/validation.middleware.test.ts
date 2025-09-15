import { Request, Response } from 'express';
import { z } from 'zod';
import { validationMiddleware } from '../../../../src/api/middlewares/validation.middleware';
import { ValidationError } from '../../../../src/domain';
import { mockLogger } from '../../../mocks/mockLogger';

describe('Validation Middleware', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let nextFunction: jest.Mock;

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

    const TestSchema = z.object({
        username: z.string({ required_error: 'Username is required' }).min(3, 'Username must be at least 3 characters'),
        email: z.string({ required_error: 'Email is required' }).email('Invalid email format'),
        age: z.number({ required_error: 'Age is required' }).min(18, 'Must be at least 18 years old').optional()
    });

    it('should pass validation for valid data', async () => {
        mockRequest.body = {
            username: 'testuser',
            email: 'test@example.com',
            age: 25
        };

        const middleware = validationMiddleware(TestSchema, mockLogger);
        await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith();
        expect(mockLogger.debug).toHaveBeenCalledWith('Request validation successful');
    });

    it('should handle validation error for missing required fields', async () => {
        mockRequest.body = {
            username: 'testuser'
            // missing email field
        };

        const middleware = validationMiddleware(TestSchema, mockLogger);
        await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith(expect.any(ValidationError));
        expect(mockLogger.warn).toHaveBeenCalledWith('Request validation failed:', expect.any(Object));
    });

    it('should handle validation error for invalid email format', async () => {
        mockRequest.body = {
            username: 'testuser',
            email: 'invalid-email'
        };

        const middleware = validationMiddleware(TestSchema, mockLogger);
        await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith(expect.any(ValidationError));
        expect(mockLogger.warn).toHaveBeenCalledWith('Request validation failed:', expect.any(Object));
    });

    it('should handle validation error for invalid username length', async () => {
        mockRequest.body = {
            username: 'ab', // too short
            email: 'test@example.com'
        };

        const middleware = validationMiddleware(TestSchema, mockLogger);
        await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith(expect.any(ValidationError));
        expect(mockLogger.warn).toHaveBeenCalledWith('Request validation failed:', expect.any(Object));
    });

    it('should pass validation when optional field is omitted', async () => {
        mockRequest.body = {
            username: 'testuser',
            email: 'test@example.com'
            // age is optional
        };

        const middleware = validationMiddleware(TestSchema, mockLogger);
        await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith();
        expect(mockLogger.debug).toHaveBeenCalledWith('Request validation successful');
    });

    it('should handle validation error for invalid optional field value', async () => {
        mockRequest.body = {
            username: 'testuser',
            email: 'test@example.com',
            age: 17 // below minimum age
        };

        const middleware = validationMiddleware(TestSchema, mockLogger);
        await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

        expect(nextFunction).toHaveBeenCalledWith(expect.any(ValidationError));
        expect(mockLogger.warn).toHaveBeenCalledWith('Request validation failed:', expect.any(Object));
    });

    it('should include all validation errors in the error message', async () => {
        mockRequest.body = {
            username: 'ab', // too short
            email: 'invalid-email', // invalid format
            age: 17 // below minimum
        };

        const middleware = validationMiddleware(TestSchema, mockLogger);
        await middleware(mockRequest as Request, mockResponse as Response, nextFunction);

        const error = nextFunction.mock.calls[0][0];
        expect(error).toBeInstanceOf(ValidationError);
        expect(error.message).toContain('Username must be at least 3 characters');
        expect(error.message).toContain('Invalid email format');
        expect(error.message).toContain('Must be at least 18 years old');
    });
});