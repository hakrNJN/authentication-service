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

    constructor(
        @inject(TYPES.Logger) private logger: ILogger,
        @inject(TYPES.ConfigService) private configService: IConfigService
    ) {
        this.useRedis = this.configService.getBoolean('USE_REDIS_BLACKLIST', false);
        if (this.useRedis) {
            const redisUrl = this.configService.getOrThrow('REDIS_URL');
            this.redisClient = new Redis(redisUrl);
            this.redisClient.on('connect', () => this.logger.info('Connected to Redis for token blacklist.'));
            this.redisClient.on('error', (err) => this.logger.error('Redis client error for token blacklist', err));
        } else {
            this.logger.warn('In-memory token blacklist is active. This is NOT suitable for production.');
        }
    }

    async addToBlacklist(tokenId: string, expirationTime: number): Promise<void> {
        if (this.redisClient) {
            await this.redisClient.setex(tokenId, expirationTime, 'blacklisted');
            this.logger.info(`Token ${tokenId} added to Redis blacklist. Expires in ${expirationTime} seconds.`);
        } else {
            // In-memory fallback
            this.logger.info(`Adding token ${tokenId} to in-memory blacklist. Expires in ${expirationTime} seconds.`);
            // Using a Map for in-memory to simulate expiration more accurately
            const expiryMap = (TokenBlacklistService as any).inMemoryBlacklist || ((TokenBlacklistService as any).inMemoryBlacklist = new Map<string, NodeJS.Timeout>());
            expiryMap.set(tokenId, setTimeout(() => {
                expiryMap.delete(tokenId);
                this.logger.info(`Token ${tokenId} removed from in-memory blacklist (expired).`);
            }, expirationTime * 1000));
        }
    }

    async isBlacklisted(tokenId: string): Promise<boolean> {
        if (this.redisClient) {
            const result = await this.redisClient.get(tokenId);
            const isBlacklisted = result === 'blacklisted';
            this.logger.debug(`Checking Redis blacklist for token ${tokenId}: ${isBlacklisted ? 'blacklisted' : 'not blacklisted'}`);
            return isBlacklisted;
        } else {
            // In-memory fallback
            const isBlacklisted = (TokenBlacklistService as any).inMemoryBlacklist?.has(tokenId) || false;
            this.logger.debug(`Checking in-memory blacklist for token ${tokenId}: ${isBlacklisted ? 'blacklisted' : 'not blacklisted'}`);
            return isBlacklisted;
        }
    }
}
