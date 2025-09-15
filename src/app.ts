import { NotFoundError } from './shared/errors/NotFoundError';
import { ValidationError } from './shared/errors/ValidationError';
import cors from 'cors';
import express, { ErrorRequestHandler, Express, NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import { createErrorMiddleware } from './api/middlewares'; // Import error middleware factory
import apiRoutes from './api/routes'; // Import aggregated API routes
import { IConfigService } from './application/interfaces/IConfigService';
import { ILogger } from './application/interfaces/ILogger';
import { ITokenBlacklistService } from './application/interfaces/ITokenBlacklistService';
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
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-grpc';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';

import { requestMetricsMiddleware } from './api/middlewares/requestMetrics.middleware';
import { ValidationError as DomainValidationError } from './domain';

export function createApp(): Express & { shutdown?: () => Promise<void> } {
    // Initialize OpenTelemetry tracing here
    const serviceName = 'authentication-service';
    const collectorEndpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'grpc://localhost:4317';

    const traceExporter = new OTLPTraceExporter({
        url: collectorEndpoint,
    });

    const spanProcessor = new BatchSpanProcessor(traceExporter);

    const sdk = new NodeSDK({
        resource: resourceFromAttributes({
            [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
        }),
        spanProcessor: spanProcessor,
        instrumentations: [getNodeAutoInstrumentations()],
    });

    sdk.start();

    // Resolve necessary dependencies for middleware setup
    const configService = container.resolve<IConfigService>(TYPES.ConfigService);
    const logger = container.resolve<ILogger>(TYPES.Logger);
    const nodeEnv = configService.get<string>('NODE_ENV', 'development');

    const app: Express = express();

    // --- Essential Middleware ---

    // 1. Security and Basic Request Processing
    app.use(helmet()); // Security headers first

    // CORS Configuration
    const corsOrigin = configService.get<string>('CORS_ORIGIN', '*');
    if (corsOrigin === '*' && nodeEnv !== 'development') {
        logger.warn('CORS origin set to "*" in non-development environment. This is insecure!');
    }
    app.use(cors({ origin: corsOrigin }));
    logger.info(`CORS configured for origin: ${corsOrigin}`);

    // 2. Content Type Validation for Auth Routes
    app.use((req: Request, res: Response, next: NextFunction) => {
        if (req.path.startsWith('/api/auth/')) {
            const contentType = req.get('content-type');
            if (req.method === 'POST' && (!contentType || !contentType.includes('application/json'))) {
                next(new ValidationError('Content-Type must be application/json'));
                return;
            }
        }
        next();
    });

    // 3. Request Body Processing
    app.use(express.json({
        verify: (req, res, buf) => {
            try {
                JSON.parse(buf.toString());
            } catch (e) {
                throw new ValidationError('Invalid JSON in request body');
            }
        }
    }));
    app.use(express.urlencoded({ extended: true }));

    // Body Parser Error Handler
    const bodyParserErrorHandler: ErrorRequestHandler = (err, req, res, next) => {
        if (err instanceof SyntaxError && 'body' in err) {
            next(new ValidationError('Invalid request body format'));
            return;
        }
        if (err instanceof ValidationError || err instanceof DomainValidationError) { // Check for both ValidationErrors
            next(err);
            return;
        }
        next(err);
    };
    app.use(bodyParserErrorHandler);

    // 4. Request Processing and Metrics
    app.use(requestMetricsMiddleware);    // TODO: Implement and add Request Logging middleware
    // app.use(createRequestLoggerMiddleware(logger));

    // --- Health Check Endpoint (REMOVED - Now handled by system.routes.ts) ---
    // app.get('/health', (req: Request, res: Response) => { ... });

    // --- API Routes ---
    app.use('/api', apiRoutes); // Mount main API routes

    // Mount test-only routes for E2E testing
    if (process.env.NODE_ENV === 'test') {
        const testRoutes = require('../tests/e2e/setup/test.routes').default;
        app.use('/api', testRoutes);
    }

    // --- Method Not Allowed and Not Found Handler ---
    app.use((req: Request, res: Response, next: NextFunction) => {
        // Get valid path from the request, removing trailing slashes and query params
        const validPath = req.path.split('?')[0].replace(/\/+$/, '');

        // Always treat unknown auth routes (/api/auth/*) as validation errors (400)
        // rather than not found errors (404)
        if (validPath.startsWith('/api/auth')) {
            // Return validation error before route matching for auth routes
            // This ensures any unknown auth routes return 400 instead of reaching the 404 handler
            next(new ValidationError(`Invalid auth request: ${req.method} ${validPath}`));
            return;
        }

        // For non-auth routes, use standard 404 handling
        next(new NotFoundError(`Not Found - ${req.method} ${req.originalUrl}`));
    });    // --- Global Error Handling Middleware (Must be LAST) ---
    // Create instance using the factory, passing dependencies
    const globalErrorHandler = createErrorMiddleware(logger, configService);
    app.use(globalErrorHandler);

    // Add shutdown method to app
    (app as any).shutdown = async (): Promise<void> => {
        logger.info('Shutting down application...');

        try {
            // Get TokenBlacklistService and disconnect Redis
            const tokenBlacklistService = container.resolve<ITokenBlacklistService>(TYPES.TokenBlacklistService);
            await tokenBlacklistService.disconnect();
        } catch (error) {
            logger.error('Error during Redis cleanup', error);
        }

        logger.info('Application shutdown complete.');
    };

    logger.info('Express application configured.');
    return app;
}

