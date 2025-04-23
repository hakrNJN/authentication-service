// Mock winston module before imports
const mockLoggerInstance = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    add: jest.fn()
};

// Create the createLogger mock
const createLoggerMock = jest.fn().mockReturnValue(mockLoggerInstance);

// Mock winston
jest.mock('winston', () => ({
    createLogger: createLoggerMock,
    format: {
        combine: jest.fn(),
        timestamp: jest.fn(),
        errors: jest.fn(),
        metadata: jest.fn(),
        json: jest.fn(),
        colorize: jest.fn(),
        printf: jest.fn(),
        splat: jest.fn()
    },
    transports: {
        Console: jest.fn(),
        File: jest.fn()
    }
}));

// Mock winston-cloudwatch
const mockCloudWatchTransport = jest.fn().mockImplementation(() => ({
    on: jest.fn(),
    emit: jest.fn(),
    log: jest.fn()
}));

jest.mock('winston-cloudwatch', () => mockCloudWatchTransport);

import { container } from 'tsyringe';
import winston from 'winston';
import { IConfigService } from '../../../../src/application/interfaces/IConfigService';
import { LogFormats } from '../../../../src/infrastructure/logging/logger.config';
import { WinstonLogger } from '../../../../src/infrastructure/logging/WinstonLogger';
import { TYPES } from '../../../../src/shared/constants/types';

// Mock LogFormats
jest.mock('../../../../src/infrastructure/logging/logger.config', () => ({
    LogFormats: {
        productionFormat: Symbol('productionFormat'),
        developmentFormat: Symbol('developmentFormat')
    }
}));

// Mock console to avoid noise during tests
const originalConsoleInfo = console.info;
console.info = jest.fn();

describe('WinstonLogger', () => {
    let logger: WinstonLogger;
    let mockConfigService: jest.Mocked<IConfigService>;

    beforeEach(() => {
        jest.clearAllMocks();
        
        mockConfigService = {
            get: jest.fn(),
            getNumber: jest.fn(),
            getBoolean: jest.fn(),
            getAllConfig: jest.fn(),
            has: jest.fn()
        };

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
        
        // Reset the createLogger mock to return a fresh instance
        createLoggerMock.mockReturnValue(mockLoggerInstance);
    });

    afterAll(() => {
        // Restore console.info
        console.info = originalConsoleInfo;
    });

    describe('Constructor', () => {
        it('should initialize with development settings', () => {
            logger = container.resolve(WinstonLogger);
            
            expect(winston.createLogger).toHaveBeenCalledWith({
                level: 'debug',
                format: LogFormats.developmentFormat,
                transports: [expect.any(Object)]
            });
            expect(winston.transports.Console).toHaveBeenCalledWith({
                level: 'debug'
            });
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

            expect(winston.createLogger).toHaveBeenCalledWith({
                level: 'info',
                format: LogFormats.productionFormat,
                transports: [expect.any(Object)]
            });
            expect(mockLoggerInstance.add).toHaveBeenCalled();
            expect(mockCloudWatchTransport).toHaveBeenCalledWith({
                logGroupName: 'test-group',
                logStreamName: 'test-stream',
                awsRegion: 'us-east-1',
            });
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