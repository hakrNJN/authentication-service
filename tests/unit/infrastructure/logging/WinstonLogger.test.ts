import { container } from 'tsyringe';
import winston from 'winston';
import CloudWatchTransport from 'winston-cloudwatch';
import { IConfigService } from '../../../../src/application/interfaces/IConfigService';
import { WinstonLogger } from '../../../../src/infrastructure/logging/WinstonLogger';
import { TYPES } from '../../../../src/shared/constants/types';

// Mock winston
jest.mock('winston', () => ({
    createLogger: jest.fn(() => ({
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        debug: jest.fn()
    })),
    transports: {
        Console: jest.fn()
    },
    format: {
        combine: jest.fn(),
        timestamp: jest.fn(),
        errors: jest.fn(),
        json: jest.fn(),
        colorize: jest.fn(),
        printf: jest.fn(),
        splat: jest.fn(),
        metadata: jest.fn()
    }
}));

// Mock winston-cloudwatch
jest.mock('winston-cloudwatch', () => {
    return jest.fn().mockImplementation(() => ({
        // Mock CloudWatch transport methods if needed
        log: jest.fn(),
        on: jest.fn()
    }));
});

describe('WinstonLogger', () => {
    let logger: WinstonLogger;
    let mockConfigService: jest.Mocked<IConfigService>;

    beforeEach(() => {
        // Reset mocks
        jest.clearAllMocks();
        
        // Create mock config service
        mockConfigService = {
            get: jest.fn(),
            getNumber: jest.fn(),
            getBoolean: jest.fn(),
            getAllConfig: jest.fn(),
            has: jest.fn(),
        };

        // Clear container and register mock
        container.clearInstances();
        container.registerInstance<IConfigService>(TYPES.ConfigService, mockConfigService);
    });

    describe('Constructor', () => {
        it('should initialize with development settings', () => {
            // Mock development environment
            mockConfigService.get.mockImplementation((key: string) => {
                switch(key) {
                    case 'LOG_LEVEL': return 'debug';
                    case 'NODE_ENV': return 'development';
                    case 'AWS_REGION': return 'us-east-1';
                    default: return undefined;
                }
            });

            logger = container.resolve(WinstonLogger);

            expect(winston.createLogger).toHaveBeenCalled();
            expect(winston.transports.Console).toHaveBeenCalled();
            expect(CloudWatchTransport).not.toHaveBeenCalled();
        });

        it('should initialize with production settings and CloudWatch', () => {
            // Mock production environment with CloudWatch settings
            mockConfigService.get.mockImplementation((key: string) => {
                switch(key) {
                    case 'LOG_LEVEL': return 'info';
                    case 'NODE_ENV': return 'production';
                    case 'AWS_REGION': return 'us-east-1';
                    case 'CW_LOG_GROUP_NAME': return 'test-group';
                    case 'CW_LOG_STREAM_NAME': return 'test-stream';
                    default: return undefined;
                }
            });

            logger = container.resolve(WinstonLogger);

            expect(winston.createLogger).toHaveBeenCalled();
            expect(winston.transports.Console).toHaveBeenCalled();
            expect(CloudWatchTransport).toHaveBeenCalled();
        });
    });

    describe('Logging Methods', () => {
        let winstonLogger: any;

        beforeEach(() => {
            // Setup basic development environment
            mockConfigService.get.mockImplementation((key: string) => {
                switch(key) {
                    case 'LOG_LEVEL': return 'debug';
                    case 'NODE_ENV': return 'development';
                    default: return undefined;
                }
            });

            logger = container.resolve(WinstonLogger);
            winstonLogger = (winston.createLogger as jest.Mock).mock.results[0].value;
        });

        it('should log info messages', () => {
            const message = 'Test info message';
            const meta = { test: 'data' };

            logger.info(message, meta);

            expect(winstonLogger.info).toHaveBeenCalledWith(message, meta);
        });

        it('should log warn messages', () => {
            const message = 'Test warning message';
            const meta = { test: 'data' };

            logger.warn(message, meta);

            expect(winstonLogger.warn).toHaveBeenCalledWith(message, meta);
        });

        it('should log error messages with Error object', () => {
            const message = 'Test error message';
            const error = new Error('Test error');
            const meta = { test: 'data' };

            logger.error(message, error, meta);

            expect(winstonLogger.error).toHaveBeenCalledWith(message, expect.objectContaining({
                ...meta,
                error: expect.objectContaining({
                    name: error.name,
                    message: error.message,
                    stack: error.stack
                })
            }));
        });

        it('should log error messages with non-Error object', () => {
            const message = 'Test error message';
            const error = { custom: 'error' };
            const meta = { test: 'data' };

            logger.error(message, error, meta);

            expect(winstonLogger.error).toHaveBeenCalledWith(message, expect.objectContaining({
                ...meta,
                error
            }));
        });

        it('should log debug messages', () => {
            const message = 'Test debug message';
            const meta = { test: 'data' };

            logger.debug(message, meta);

            expect(winstonLogger.debug).toHaveBeenCalledWith(message, meta);
        });
    });
});