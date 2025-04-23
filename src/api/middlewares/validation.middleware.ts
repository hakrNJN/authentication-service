import { RequestHandler } from 'express';
import { z } from 'zod';
import { ILogger } from '../../application/interfaces/ILogger';
import { ValidationError } from '../../domain';

export const validationMiddleware = (schema: z.Schema, logger: ILogger): RequestHandler => {
    return async (req, res, next) => {
        try {
            // Parse and validate the request body
            const validatedData = await schema.parseAsync(req.body);
            
            // Update request body with validated and transformed data
            req.body = validatedData;
            logger.debug('Request validation successful');
            next();
        } catch (error) {
            if (error instanceof z.ZodError) {
                const messages = error.errors.map(e => {
                    const path = e.path.join('.');
                    return path ? `${path}: ${e.message}` : e.message;
                });
                
                logger.warn('Request validation failed:', { 
                    errors: error.errors,
                    body: req.body 
                });
                
                next(new ValidationError(messages.join('; ')));
            } else {
                logger.error('Unexpected validation error:', error);
                next(error);
            }
        }
    };
};

