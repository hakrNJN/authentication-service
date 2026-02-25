import rateLimit, { RateLimitRequestHandler } from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { IConfigService } from '../../application/interfaces/IConfigService';
import Redis from 'ioredis';

export class RateLimiterFactory {
    private readonly redisClient: Redis | null = null;
    private readonly isRedisEnabled: boolean;

    constructor(private readonly configService: IConfigService) {
        const redisUrl = this.configService.get('REDIS_URL');
        this.isRedisEnabled = !!redisUrl;

        if (this.isRedisEnabled && redisUrl) {
            this.redisClient = new Redis(redisUrl, {
                maxRetriesPerRequest: 1, // Don't hang if Redis is down
                enableReadyCheck: false
            });

            this.redisClient.on('error', (err) => {
                console.warn('[RateLimiterFactory] Redis connection error, falling back to memory store if necessary:', err.message);
            });
        }
    }

    /**
     * Creates an Express rate limiting middleware.
     * Uses Redis store if configured, otherwise falls back to the built-in memory store.
     * 
     * @param windowMs Time window in milliseconds
     * @param max Requests allowed per window
     * @param message Custom message to return when limit is exceeded
     */
    public createLimiter(windowMs: number, max: number, message = 'Too many requests, please try again later.'): RateLimitRequestHandler {
        return rateLimit({
            windowMs,
            max,
            message: {
                success: false,
                error: message
            },
            standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
            legacyHeaders: false, // Disable the `X-RateLimit-*` headers
            store: this.redisClient ? new RedisStore({
                sendCommand: (...args: string[]) => this.redisClient!.call(args[0], ...args.slice(1)) as any,
            }) : undefined, // Undefined store falls back to memory
        });
    }

    public getAuthLimiter(): RateLimitRequestHandler {
        // Default: 5 requests per 60 seconds for login & registration
        const windowMsStr = this.configService.get('AUTH_RATE_LIMIT_WINDOW_MS') || '60000';
        const maxStr = this.configService.get('AUTH_RATE_LIMIT_MAX') || '5';
        const windowMs = parseInt(windowMsStr, 10);
        const max = parseInt(maxStr, 10);

        return this.createLimiter(windowMs, max, 'Too many authentication attempts. Please try again in a minute.');
    }
}
