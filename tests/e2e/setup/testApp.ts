import express, { Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { setupTestContainer } from './testContainer';
import { container } from 'tsyringe';
import { TYPES } from '../../../src/shared/constants/types';
import { ILogger } from '../../../src/application/interfaces/ILogger';
import { IConfigService } from '../../../src/application/interfaces/IConfigService';
import { ITokenBlacklistService } from '../../../src/application/interfaces/ITokenBlacklistService';
import authRoutes from '../../../src/api/routes/auth.routes';
import systemRoutes from '../../../src/api/routes/system.routes';
import { createErrorMiddleware } from '../../../src/api/middlewares/error.middleware';
import { requestMetricsMiddleware } from '../../../src/api/middlewares/requestMetrics.middleware';

export function createTestApp(): Express & { shutdown?: () => Promise<void> } {
    const app = express() as Express & { shutdown?: () => Promise<void> };
    
    // Setup test container with mocked services
    setupTestContainer();
    
    const logger = container.resolve<ILogger>(TYPES.Logger);
    const configService = container.resolve<IConfigService>(TYPES.ConfigService);

    // Security middleware
    app.use(helmet());
    app.use(cors());

    // Request metrics
    app.use(requestMetricsMiddleware);

    // Body parsing middleware
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Routes
    app.use('/api/auth', authRoutes);
    app.use('/api/system', systemRoutes);

    // Error handling middleware (must be last)
    app.use(createErrorMiddleware(logger, configService));

    // Add shutdown method
    app.shutdown = async (): Promise<void> => {
        logger.info('Shutting down test application...');
        
        try {
            const tokenBlacklistService = container.resolve<ITokenBlacklistService>(TYPES.TokenBlacklistService);
            await tokenBlacklistService.disconnect();
        } catch (error) {
            logger.error('Error during test app cleanup', error);
        }
        
        logger.info('Test application shutdown complete.');
    };

    logger.info('Test Express application configured.');
    return app;
}