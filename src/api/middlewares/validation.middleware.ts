import { RequestHandler } from 'express';
import { z } from 'zod';
import { ILogger } from '../../application/interfaces/ILogger';
import { ValidationError } from '../../domain';

export const validationMiddleware = (schema: z.Schema, logger: ILogger): RequestHandler => {
    return (req, res, next): void => {
        logger.debug(`Validation Middleware - Request URL: ${req.originalUrl}, Method: ${req.method}`);
        logger.debug(`Validation Middleware - Request Body (before validation): ${JSON.stringify(req.body)}`);

        // Check if request has a body when required
        if (schema && !req.body) {
            logger.warn('Request validation failed: Missing request body');
            next(new ValidationError('Request body is required'));
            return;
        }

        try {
            // Use safeParse instead of parse to handle validation errors more gracefully
            const result = schema.safeParse(req.body);

            if (!result.success) {
                const error = result.error;
                const messages = error.errors.map(e => {
                    const path = e.path.join('.');
                    return path ? `${path}: ${e.message}` : e.message;
                });

                logger.warn('Request validation failed:', {
                    errors: error.errors,
                    body: req.body
                });

                next(new ValidationError(messages.join('; ')));
                return;
            }

            // If validation succeeds, update req.body with validated data
            req.body = result.data;
            logger.debug('Request validation successful');
            next();
        } catch (error) {
            logger.error('Unexpected validation error:', error);
            next(new Error('An unexpected error occurred during validation'));
        }
    };
};

