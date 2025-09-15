import { ErrorRequestHandler } from 'express';
import { IConfigService } from '../../application/interfaces/IConfigService';
import { ILogger } from '../../application/interfaces/ILogger';
import { AuthenticationError, InvalidCredentialsError, MfaRequiredError, ValidationError } from '../../domain';
import { BaseError } from '../../shared/errors/BaseError';

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
    return (err: Error | string, req, res, next) => {
        // If headers already sent, delegate to default Express error handler
        if (res.headersSent) {
            logger.warn('Error occurred after headers were sent, delegating to default handler.', {
                errorName: err instanceof Error ? err.name : typeof err,
                path: req.originalUrl
            });
            return next(err);
        }

        const isDevelopment = configService.get('NODE_ENV') === 'development';
        const error = err instanceof Error ? err : new Error(String(err));

        // Log errors appropriately
        if (error instanceof BaseError) {
            logger.error(error.message, error);
        } else if (error instanceof ValidationError) {
            logger.error(`Error processing request ${req.method} ${req.originalUrl}: ${error.message}`, error);
        } else {
            logger.error(`Error processing request ${req.method} ${req.originalUrl}: ${error.name}`, error);
        }

        // Determine status code based on error type
        let statusCode = 500;
        if (error instanceof ValidationError) {
            statusCode = 400;
        } else if (error instanceof InvalidCredentialsError) {
            statusCode = 401;
        } else if (error instanceof MfaRequiredError) {
            statusCode = 401;  // MFA challenges should return 401
        } else if (error instanceof AuthenticationError) {
            statusCode = 401;
        } else if (error instanceof BaseError) {
            statusCode = error.statusCode || (error.name === 'NotFoundError' ? 404 : 500);
        }

        logger.debug(`Error Middleware - Processing error: ${error.name}, Message: ${error.message}, Determined Status Code: ${statusCode}`);
        logger.debug(`Error Middleware - Error instance: ${JSON.stringify(error)}`);

        // Prepare response
        const response: any = {
            status: 'error',
            name: isDevelopment ? error.name : (statusCode === 500 ? 'InternalServerError' : error.name),
            message: isDevelopment || statusCode !== 500 ? error.message : 'An unexpected error occurred',
            ...(isDevelopment && error.stack && { stack: error.stack })
        };

        // Add special properties for MfaRequiredError
        if (error instanceof MfaRequiredError) {
            response.session = error.session;
            response.challengeName = error.challengeName;
            response.challengeParameters = error.challengeParameters;
        }

        res.status(statusCode).json(response);
    };
};

