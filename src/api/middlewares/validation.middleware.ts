import { NextFunction, Request, Response } from 'express';
import { AnyZodObject, ZodError } from 'zod';
import { ILogger } from '../../application/interfaces/ILogger'; // Optional: for logging validation errors
import { ValidationError } from '../../domain'; // Import custom ValidationError

/**
 * Factory function that creates an Express middleware for validating request data
 * (body, query params, route params) against a provided Zod schema.
 *
 * @param schema - The Zod schema (AnyZodObject) to validate against.
 * @param logger - Optional logger instance for logging validation errors.
 * @returns An Express middleware function.
 */
export const validationMiddleware = (schema: AnyZodObject, logger?: ILogger) =>
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            // Validate the entire request object (allows validating body, query, params together)
            await schema.parseAsync({
                body: req.body,
                query: req.query,
                params: req.params,
            });
            // Validation successful, proceed to the next middleware/handler
            next();
        } catch (error) {
            if (error instanceof ZodError) {
                // Log the detailed Zod error if logger is available
                logger?.warn('Request validation failed:', { errors: error.errors });

                // Format Zod errors into a user-friendly structure
                const formattedErrors = error.errors.reduce((acc, currentError) => {
                    const path = currentError.path.join('.');
                    acc[path] = currentError.message;
                    return acc;
                }, {} as Record<string, string>);

                // Create a custom ValidationError instance
                const validationError = new ValidationError(
                    'Input validation failed',
                    formattedErrors // Pass formatted details
                );
                // Pass the custom error to the global error handler
                next(validationError);
            } else {
                // Pass unexpected errors to the global error handler
                logger?.error('Unexpected error during validation middleware:', error);
                next(error);
            }
        }
    };

