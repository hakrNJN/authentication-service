import { inject, injectable } from 'tsyringe';
import winston, { Logger, transports } from 'winston';
import CloudWatchTransport from 'winston-cloudwatch'; // Import CloudWatch transport
import { IConfigService } from '../../application/interfaces/IConfigService';
import { ILogger } from '../../application/interfaces/ILogger';
import { TYPES } from '../../shared/constants/types';
import { LogFormats } from './logger.config'; // Import reusable formats

@injectable()
export class WinstonLogger implements ILogger {
    private readonly logger: Logger;

    constructor(@inject(TYPES.ConfigService) private configService: IConfigService) {
        const logLevel = this.configService.get<string>('LOG_LEVEL', 'debug');
        const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');

        // Use formats defined in logger.config.ts
        const logFormat = nodeEnv === 'production'
            ? LogFormats.productionFormat
            : LogFormats.developmentFormat;

        // Define transports
        const loggerTransports: winston.transport[] = [
            new transports.Console({
                 // stderrLevels: ['error'], // Optionally send errors to stderr
            }),
        ];

        // --- Add CloudWatch Transport for Production ---
        if (nodeEnv === 'production') {
            const cwLogGroupName = this.configService.get<string>('CW_LOG_GROUP_NAME');
            const cwLogStreamName = this.configService.get<string>('CW_LOG_STREAM_NAME'); // e.g., 'auth-service-instance-id' or dynamic name
            const awsRegion = this.configService.get<string>('AWS_REGION'); // Should already be required

            if (cwLogGroupName && cwLogStreamName && awsRegion) {
                try {
                    const cloudWatchTransport = new CloudWatchTransport({
                        logGroupName: cwLogGroupName,
                        logStreamName: cwLogStreamName,
                        // Credentials should be handled via IAM Role (recommended) or environment variables
                        // awsOptions: { region: awsRegion }, // Region might be picked up automatically too
                        // Ensure AWS SDK v3 compatibility if needed, or configure v2 if used by the library
                        // Check winston-cloudwatch documentation for specific credential/region config if needed
                        jsonMessage: true, // Send logs as JSON
                        messageFormatter: (logObject) => {
                            // Ensure the message is properly formatted, especially errors
                            const { level, message, stack, ...meta } = logObject;
                             // Include stack trace directly if present
                             const logEntry = { level, message, stack, ...meta };
                             return JSON.stringify(logEntry);
                        },
                        level: logLevel, // Use the same log level
                    });
                     loggerTransports.push(cloudWatchTransport);
                     console.info(`[WinstonLogger] CloudWatch transport configured for group "${cwLogGroupName}" and stream "${cwLogStreamName}"`); // Use console here
                } catch (error) {
                    console.error('[WinstonLogger] Failed to configure CloudWatch transport:', error); // Use console here
                }
            } else {
                 console.warn('[WinstonLogger] CloudWatch logging enabled in production but required configuration (CW_LOG_GROUP_NAME, CW_LOG_STREAM_NAME) is missing.');
            }
        }

        this.logger = winston.createLogger({
            level: logLevel,
            format: logFormat,
            transports: loggerTransports,
            exitOnError: false, // Do not exit on handled exceptions
        });

        // Use console here as logger might not be fully ready with async transports
        console.info(`[WinstonLogger] Logger initialized with level "${logLevel}" in "${nodeEnv}" environment.`);
    }

    info(message: string, meta?: Record<string, any>): void {
        this.logger.info(message, meta);
    }

    warn(message: string, meta?: Record<string, any>): void {
        this.logger.warn(message, meta);
    }

    error(message: string, error?: Error | any, meta?: Record<string, any>): void {
        // Ensure error object is properly included in metadata for transports like CloudWatch
        const logMeta = {
             ...meta,
             // Include error details if it's an Error object
             ...(error instanceof Error && { error: { name: error.name, message: error.message, stack: error.stack } }),
             // Include raw error if not an Error instance
             ...(!(error instanceof Error) && error !== undefined && { error }) // Add non-Error object if present
        };
        this.logger.error(message, logMeta);
    }

    debug(message: string, meta?: Record<string, any>): void {
        this.logger.debug(message, meta);
    }
}
