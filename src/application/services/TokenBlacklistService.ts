import { injectable, inject } from 'tsyringe';
import { ITokenBlacklistService } from '../interfaces/ITokenBlacklistService';
import { ILogger } from '../interfaces/ILogger';
import { TYPES } from '../../shared/constants/types';
import { IConfigService } from '../interfaces/IConfigService';
import Redis from 'ioredis';

// TODO: CRITICAL: For production, this in-memory blacklist MUST be replaced with a distributed, persistent cache like Redis.
// This ensures that the blacklist is shared across all instances of the service and survives restarts.
// The current implementation is for demonstration and development purposes ONLY.

@injectable()
export class TokenBlacklistService implements ITokenBlacklistService {
    private redisClient: Redis | null = null;
    private readonly useRedis: boolean;
    private isRedisConnected: boolean = false;

    constructor(
        @inject(TYPES.Logger) private logger: ILogger,
        @inject(TYPES.ConfigService) private configService: IConfigService
    ) {
        this.useRedis = this.configService.getBoolean('USE_REDIS_BLACKLIST') ?? false;
        if (this.useRedis) {
            this.initializeRedis();
        } else {
            this.logger.warn('In-memory token blacklist is active. This is NOT suitable for production.');
        }
    }

    private initializeRedis(): void {
        try {
            const redisUrl = this.configService.getOrThrow<string>('REDIS_URL');
            this.redisClient = new Redis(redisUrl, {
                maxRetriesPerRequest: 3,
                lazyConnect: true,
                connectTimeout: 5000,
                commandTimeout: 5000,
            });

            this.redisClient.on('connect', () => {
                this.isRedisConnected = true;
                this.logger.info('Connected to Redis for token blacklist.');
            });

            this.redisClient.on('error', (err) => {
                this.isRedisConnected = false;
                this.logger.error('Redis client error for token blacklist', { error: err.message, stack: err.stack });
            });

            this.redisClient.on('close', () => {
                this.isRedisConnected = false;
                this.logger.warn('Redis connection closed for token blacklist.');
            });

            this.redisClient.on('reconnecting', () => {
                this.logger.info('Reconnecting to Redis for token blacklist...');
            });

        } catch (error) {
            this.logger.error('Failed to initialize Redis client for token blacklist', error);
            this.redisClient = null;
        }
    }

    async disconnect(): Promise<void> {
        if (this.redisClient) {
            try {
                await this.redisClient.quit();
                this.logger.info('Redis client disconnected for token blacklist.');
            } catch (error) {
                this.logger.error('Error disconnecting Redis client', error);
            }
        }
    }

    async addToBlacklist(tokenId: string, expirationTime: number): Promise<void> {
        if (this.redisClient && this.useRedis) {
            try {
                // Ensure connection is established
                if (!this.isRedisConnected) {
                    await this.redisClient.connect();
                }
                await this.redisClient.setex(tokenId, expirationTime, 'blacklisted');
                this.logger.info(`Token ${tokenId} added to Redis blacklist. Expires in ${expirationTime} seconds.`);
                return;
            } catch (error) {
                this.logger.error(`Failed to add token ${tokenId} to Redis blacklist, falling back to in-memory`, error);
                // Fall through to in-memory fallback
            }
        }

        // In-memory fallback
        this.logger.info(`Adding token ${tokenId} to in-memory blacklist. Expires in ${expirationTime} seconds.`);
        // Using a Map for in-memory to simulate expiration more accurately
        const expiryMap = (TokenBlacklistService as any).inMemoryBlacklist || ((TokenBlacklistService as any).inMemoryBlacklist = new Map<string, NodeJS.Timeout>());
        
        // Clear existing timeout if token already exists
        if (expiryMap.has(tokenId)) {
            clearTimeout(expiryMap.get(tokenId));
        }
        
        expiryMap.set(tokenId, setTimeout(() => {
            expiryMap.delete(tokenId);
            this.logger.info(`Token ${tokenId} removed from in-memory blacklist (expired).`);
        }, expirationTime * 1000));
    }

    async isBlacklisted(tokenId: string): Promise<boolean> {
        if (this.redisClient && this.useRedis) {
            try {
                // Ensure connection is established
                if (!this.isRedisConnected) {
                    await this.redisClient.connect();
                }
                const result = await this.redisClient.get(tokenId);
                const isBlacklisted = result === 'blacklisted';
                this.logger.debug(`Checking Redis blacklist for token ${tokenId}: ${isBlacklisted ? 'blacklisted' : 'not blacklisted'}`);
                return isBlacklisted;
            } catch (error) {
                this.logger.error(`Failed to check Redis blacklist for token ${tokenId}, falling back to in-memory`, error);
                // Fall through to in-memory fallback
            }
        }

        // In-memory fallback
        const isBlacklisted = (TokenBlacklistService as any).inMemoryBlacklist?.has(tokenId) || false;
        this.logger.debug(`Checking in-memory blacklist for token ${tokenId}: ${isBlacklisted ? 'blacklisted' : 'not blacklisted'}`);
        return isBlacklisted;
    }
}
