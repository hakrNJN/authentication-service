// Create a singleton mock logger instance
const mockLoggerInstance = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    add: jest.fn()
};

// Mock winston module before imports
jest.mock('winston', () => ({
    createLogger: jest.fn().mockReturnValue(mockLoggerInstance),
    transports: {
        Console: jest.fn()
    },
    format: {
        combine: jest.fn().mockReturnValue({}),
        timestamp: jest.fn().mockReturnValue({}),
        errors: jest.fn().mockReturnValue({}),
        json: jest.fn().mockReturnValue({}),
        colorize: jest.fn().mockReturnValue({}),
        printf: jest.fn().mockReturnValue({}),
        splat: jest.fn().mockReturnValue({}),
        metadata: jest.fn().mockReturnValue({})
    }
}));

// Mock winston-cloudwatch
const mockCloudWatchTransport = {
    on: jest.fn(),
    emit: jest.fn(),
    log: jest.fn()
};

jest.mock('winston-cloudwatch', () => jest.fn().mockImplementation(() => mockCloudWatchTransport));

import { container } from 'tsyringe';
import winston from 'winston';
import { IConfigService } from '../../../../src/application/interfaces/IConfigService';
import { WinstonLogger } from '../../../../src/infrastructure/logging/WinstonLogger';
import { TYPES } from '../../../../src/shared/constants/types';

describe('WinstonLogger', () => {
    let logger: WinstonLogger;
    let mockConfigService: jest.Mocked<IConfigService>;

    beforeEach(() => {
        // Reset all mocks
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

        // Setup basic development environment
        mockConfigService.get.mockImplementation((key: string) => {
            switch(key) {
                case 'LOG_LEVEL': return 'debug';
                case 'NODE_ENV': return 'development';
                default: return undefined;
            }
        });
    });

    describe('Constructor', () => {
        it('should initialize with development settings', () => {
            logger = container.resolve(WinstonLogger);
            
            expect(winston.createLogger).toHaveBeenCalled();
            expect(winston.transports.Console).toHaveBeenCalled();
            expect(mockLoggerInstance).toBeDefined();
        });

        it('should initialize with production settings and CloudWatch', () => {
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
            expect(mockLoggerInstance.add).toHaveBeenCalledTimes(1);
        });
    });

    describe('Logging Methods', () => {
        beforeEach(() => {
            logger = container.resolve(WinstonLogger);
        });

        it('should log info messages', () => {
            const message = 'Test info message';
            const meta = { test: 'data' };

            logger.info(message, meta);

            expect(mockLoggerInstance.info).toHaveBeenCalledWith(message, meta);
        });

        it('should log warn messages', () => {
            const message = 'Test warning message';
            const meta = { test: 'data' };

            logger.warn(message, meta);

            expect(mockLoggerInstance.warn).toHaveBeenCalledWith(message, meta);
        });

        it('should log error messages with Error object', () => {
            const message = 'Test error message';
            const error = new Error('Test error');
            const meta = { test: 'data' };

            logger.error(message, error, meta);

            expect(mockLoggerInstance.error).toHaveBeenCalledWith(message, {
                ...meta,
                error: {
                    name: error.name,
                    message: error.message,
                    stack: error.stack
                }
            });
        });

        it('should log error messages with non-Error object', () => {
            const message = 'Test error message';
            const error = { custom: 'error' };
            const meta = { test: 'data' };

            logger.error(message, error, meta);

            expect(mockLoggerInstance.error).toHaveBeenCalledWith(message, {
                ...meta,
                error
            });
        });

        it('should log debug messages', () => {
            const message = 'Test debug message';
            const meta = { test: 'data' };

            logger.debug(message, meta);

            expect(mockLoggerInstance.debug).toHaveBeenCalledWith(message, meta);
        });
    });
});