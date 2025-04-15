import { ErrorRequestHandler, NextFunction, Request, Response } from 'express';
import { IConfigService } from '../../application/interfaces/IConfigService';
import { ILogger } from '../../application/interfaces/ILogger';
import { BaseError } from '../../shared/errors/BaseError'; // Adjust path if BaseError moves

/**
 * Factory function to create the global error handling middleware.
 * This approach allows injecting dependencies like logger and config service during setup.
 *
 * @param logger - An instance of the logger service.
 * @param configService - An instance of the configuration service.
 * @returns An Express ErrorRequestHandler function.
 */
export const createErrorMiddleware = (
    logger: ILogger,
    configService: IConfigService
): ErrorRequestHandler => {
    // Return the actual middleware function
    return (err: Error, req: Request, res: Response, next: NextFunction): void => {
        // If headers already sent, delegate to default Express error handler
        if (res.headersSent) {
            logger.warn('Error occurred after headers were sent, delegating to default handler.', { errorName: err.name, path: req.path });
            return next(err);
        }

        // Log the error with context
        logger.error(`Error processing request ${req.method} ${req.originalUrl}: ${err.message}`, err);

        const isDevelopment = configService.get('NODE_ENV') === 'development';

        if (err instanceof BaseError && err.isOperational) {
            // Known operational errors (Validation, NotFound, Auth, etc.)
             res.status(err.statusCode).json({
                status: 'error',
                name: err.name,
                message: err.message,
                // Optionally include stack trace and details in development
                ...(isDevelopment && {
                    stack: err.stack,
                    details: (err as any).details // Include details if present (e.g., from ValidationError)
                 }),
            });
        } else {
            // Unknown/programmer errors - avoid leaking details in production
             res.status(500).json({
                status: 'error',
                name: isDevelopment && err instanceof Error ? err.name : 'InternalServerError',
                message: isDevelopment && err instanceof Error ? err.message : 'An unexpected internal server error occurred.',
                 // Optionally include stack trace in development
                ...(isDevelopment && err instanceof Error && { stack: err.stack }),
            });
        }
    };
};

