import { inject, injectable } from 'tsyringe';
import winston from 'winston';
import CloudWatchTransport from 'winston-cloudwatch';
import { IConfigService } from '../../application/interfaces/IConfigService';
import { ILogger } from '../../application/interfaces/ILogger';
import { TYPES } from '../../shared/constants/types';

type NodeEnv = 'development' | 'production' | 'test';

@injectable()
export class WinstonLogger implements ILogger {
    private _logger: winston.Logger;

    constructor(
        @inject(TYPES.ConfigService) private configService: IConfigService
    ) {
        const logLevel = this.configService.get('LOG_LEVEL', 'info');
        const nodeEnv = this.configService.get<NodeEnv>('NODE_ENV', 'development');

        // Create base logger with console transport
        this._logger = winston.createLogger({
            level: logLevel,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.metadata(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.Console()
            ]
        });

        // Add CloudWatch transport in production
        if (nodeEnv === 'production') {
            const awsRegion = this.configService.get('AWS_REGION');
            const logGroupName = this.configService.get('CW_LOG_GROUP_NAME');
            const logStreamName = this.configService.get('CW_LOG_STREAM_NAME');

            if (awsRegion && logGroupName) {
                const cloudWatchTransport = new CloudWatchTransport({
                    logGroupName,
                    logStreamName: logStreamName || 'default',
                    awsRegion,
                });

                this._logger.add(cloudWatchTransport);
                console.info(`[WinstonLogger] CloudWatch transport configured for group "${logGroupName}" and stream "${logStreamName}"`);
            }
        }

        console.info(`[WinstonLogger] Logger initialized with level "${logLevel}" in "${nodeEnv}" environment.`);
    }

    get logger(): winston.Logger {
        if (!this._logger) {
            throw new Error('Logger not initialized');
        }
        return this._logger;
    }

    info(message: string, meta?: Record<string, any>): void {
        if (!message) return;
        this.logger.info(message, meta);
    }

    warn(message: string, meta?: Record<string, any>): void {
        if (!message) return;
        this.logger.warn(message, meta);
    }

    error(message: string, error?: Error | any, meta?: Record<string, any>): void {
        if (!message) return;
        const logMeta = {
            ...meta,
            ...(error instanceof Error && {
                error: {
                    name: error.name,
                    message: error.message,
                    stack: error.stack
                }
            }),
            ...(!(error instanceof Error) && error !== undefined && { error })
        };
        this.logger.error(message, logMeta);
    }

    debug(message: string, meta?: Record<string, any>): void {
        if (!message) return;
        this.logger.debug(message, meta);
    }
}
