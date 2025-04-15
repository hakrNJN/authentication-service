import cors from 'cors';
import express, { Express, NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import { createErrorMiddleware } from './api/middlewares'; // Import error middleware factory
import apiRoutes from './api/routes'; // Import aggregated API routes
import { IConfigService } from './application/interfaces/IConfigService';
import { ILogger } from './application/interfaces/ILogger';
import { container } from './container'; // Import DI container to resolve dependencies if needed by middleware factories
import { TYPES } from './shared/constants/types';
// Import other middleware factories/functions as needed
// import { createRequestLoggerMiddleware } from './api/middlewares';
// import { createRequestIdMiddleware } from './api/middlewares';

/**
 * Creates and configures the Express application instance.
 * Encapsulates middleware setup, routing, and error handling.
 *
 * @returns The configured Express application.
 */
export function createApp(): Express {
    // Resolve necessary dependencies for middleware setup
    const configService = container.resolve<IConfigService>(TYPES.ConfigService);
    const logger = container.resolve<ILogger>(TYPES.Logger);
    const nodeEnv = configService.get<string>('NODE_ENV', 'development');

    const app: Express = express();

    // --- Essential Middleware ---

    // TODO: Implement and add Request ID middleware
    // app.use(createRequestIdMiddleware());

    // Security Headers
    app.use(helmet());

    // CORS Configuration
    const corsOrigin = configService.get<string>('CORS_ORIGIN', '*'); // Default to '*' BUT WARN
    if (corsOrigin === '*' && nodeEnv !== 'development') {
        logger.warn('CORS origin set to "*" in non-development environment. This is insecure!');
    }
    app.use(cors({ origin: corsOrigin })); // Read allowed origin from config
    logger.info(`CORS configured for origin: ${corsOrigin}`);

    // Body Parsers
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // TODO: Implement and add Request Logging middleware
    // app.use(createRequestLoggerMiddleware(logger));

    // --- Health Check Endpoint (REMOVED - Now handled by system.routes.ts) ---
    // app.get('/health', (req: Request, res: Response) => { ... });

    // --- API Routes ---
    app.use('/api', apiRoutes); // Mount main API routes

    // --- Not Found Handler (Optional but recommended) ---
    app.use((req: Request, res: Response, next: NextFunction) => {
        // Create a NotFoundError instance and pass it to the error handler
        // This ensures consistent error formatting
        const err = new Error(`Not Found - ${req.method} ${req.originalUrl}`);
        (err as any).statusCode = 404; // Add status code for error handler
        next(err); // Pass to global error handler
    });

    // --- Global Error Handling Middleware (Must be LAST) ---
    // Create instance using the factory, passing dependencies
    const globalErrorHandler = createErrorMiddleware(logger, configService);
    app.use(globalErrorHandler);

    logger.info('Express application configured.');
    return app;
}

