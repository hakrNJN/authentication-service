import { TokenBlacklistService } from '../../../../src/application/services/TokenBlacklistService';
import { ILogger } from '../../../../src/application/interfaces/ILogger';
import { IConfigService } from '../../../../src/application/interfaces/IConfigService';
import Redis from 'ioredis';

// Mock Redis
jest.mock('ioredis');
const MockedRedis = Redis as jest.MockedClass<typeof Redis>;

describe('TokenBlacklistService', () => {
  let service: TokenBlacklistService;
  let mockLogger: jest.Mocked<ILogger>;
  let mockConfigService: jest.Mocked<IConfigService>;
  let mockRedisInstance: jest.Mocked<Redis>;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Clear static in-memory blacklist and any existing timers
    const existingMap = (TokenBlacklistService as any).inMemoryBlacklist;
    if (existingMap) {
      // Clear all existing timers
      existingMap.forEach((timeout: NodeJS.Timeout) => {
        clearTimeout(timeout);
      });
    }
    (TokenBlacklistService as any).inMemoryBlacklist = new Map();

    // Create mock instances
    mockLogger = {
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn()
    } as jest.Mocked<ILogger>;

    mockConfigService = {
      get: jest.fn(),
      getNumber: jest.fn(),
      getBoolean: jest.fn(),
      getAllConfig: jest.fn(),
      has: jest.fn(),
      getOrThrow: jest.fn()
    } as jest.Mocked<IConfigService>;

    mockRedisInstance = {
      setex: jest.fn(),
      get: jest.fn(),
      del: jest.fn(),
      disconnect: jest.fn(),
      quit: jest.fn(),
      connect: jest.fn(),
      on: jest.fn(),
      ping: jest.fn()
    } as any;

    // Mock Redis constructor
    MockedRedis.mockImplementation(() => mockRedisInstance);

    // Default config values
    mockConfigService.getBoolean.mockImplementation((key: string) => {
      if (key === 'USE_REDIS_BLACKLIST') return true;
      return false;
    });

    mockConfigService.getOrThrow.mockImplementation((key: string) => {
      if (key === 'REDIS_URL') return 'redis://localhost:6379';
      throw new Error(`Config key ${key} not found`);
    });
  });

  afterEach(() => {
    // Clean up any remaining timers
    const existingMap = (TokenBlacklistService as any).inMemoryBlacklist;
    if (existingMap) {
      existingMap.forEach((timeout: NodeJS.Timeout) => {
        clearTimeout(timeout);
      });
      existingMap.clear();
    }
  });

  describe('Constructor and Initialization', () => {
    it('should initialize with Redis when USE_REDIS_BLACKLIST is true', () => {
      service = new TokenBlacklistService(mockLogger, mockConfigService);

      expect(MockedRedis).toHaveBeenCalledWith('redis://localhost:6379', expect.any(Object));
      expect(mockRedisInstance.on).toHaveBeenCalledWith('connect', expect.any(Function));
      expect(mockRedisInstance.on).toHaveBeenCalledWith('error', expect.any(Function));
    });

    it('should initialize with in-memory storage when USE_REDIS_BLACKLIST is false', () => {
      mockConfigService.getBoolean.mockImplementation((key: string) => {
        if (key === 'USE_REDIS_BLACKLIST') return false;
        return false;
      });

      service = new TokenBlacklistService(mockLogger, mockConfigService);

      expect(MockedRedis).not.toHaveBeenCalled();
      expect(mockLogger.warn).toHaveBeenCalledWith('In-memory token blacklist is active. This is NOT suitable for production.');
    });

    it('should handle Redis connection errors', () => {
      service = new TokenBlacklistService(mockLogger, mockConfigService);

      // Simulate Redis error
      const errorHandler = mockRedisInstance.on.mock.calls.find(call => call[0] === 'error')?.[1];
      const testError = new Error('Redis connection failed');

      if (errorHandler) {
        errorHandler(testError);
      }

      expect(mockLogger.error).toHaveBeenCalledWith('Redis client error for token blacklist', expect.objectContaining({
        error: 'Redis connection failed'
      }));
    });

    it('should handle Redis initialization failure', () => {
      mockConfigService.getOrThrow.mockImplementation(() => {
        throw new Error('Redis URL not configured');
      });

      service = new TokenBlacklistService(mockLogger, mockConfigService);

      expect(mockLogger.error).toHaveBeenCalledWith('Failed to initialize Redis client for token blacklist', expect.any(Error));
    });
  });

  describe('addToBlacklist', () => {
    beforeEach(() => {
      service = new TokenBlacklistService(mockLogger, mockConfigService);
    });

    it('should add token to Redis blacklist successfully', async () => {
      const token = 'test-token';
      const expirationTime = 3600;
      mockRedisInstance.connect.mockResolvedValue(undefined);
      mockRedisInstance.setex.mockResolvedValue('OK');

      await service.addToBlacklist(token, expirationTime);

      expect(mockRedisInstance.setex).toHaveBeenCalledWith(token, expirationTime, 'blacklisted');
      expect(mockLogger.info).toHaveBeenCalledWith(`Token ${token} added to Redis blacklist. Expires in ${expirationTime} seconds.`);
    });

    it('should handle Redis setex errors and fallback to in-memory', async () => {
      const token = 'test-token';
      const expirationTime = 3600;
      const error = new Error('Redis setex failed');
      mockRedisInstance.connect.mockResolvedValue(undefined);
      mockRedisInstance.setex.mockRejectedValue(error);

      await service.addToBlacklist(token, expirationTime);

      expect(mockLogger.error).toHaveBeenCalledWith(`Failed to add token ${token} to Redis blacklist, falling back to in-memory`, error);
      expect(mockLogger.info).toHaveBeenCalledWith(`Adding token ${token} to in-memory blacklist. Expires in ${expirationTime} seconds.`);
    });

    it('should add token to in-memory blacklist when Redis is disabled', async () => {
      // Create service with Redis disabled
      mockConfigService.getBoolean.mockImplementation((key: string) => {
        if (key === 'USE_REDIS_BLACKLIST') return false;
        return false;
      });

      service = new TokenBlacklistService(mockLogger, mockConfigService);

      const token = 'test-token';
      const expirationTime = 3600;

      await service.addToBlacklist(token, expirationTime);

      expect(mockLogger.info).toHaveBeenCalledWith(`Adding token ${token} to in-memory blacklist. Expires in ${expirationTime} seconds.`);
    });

    it('should handle Redis connection failure and fallback to in-memory', async () => {
      const token = 'test-token';
      const expirationTime = 3600;
      const error = new Error('Connection failed');
      mockRedisInstance.connect.mockRejectedValue(error);

      await service.addToBlacklist(token, expirationTime);

      expect(mockLogger.error).toHaveBeenCalledWith(`Failed to add token ${token} to Redis blacklist, falling back to in-memory`, error);
      expect(mockLogger.info).toHaveBeenCalledWith(`Adding token ${token} to in-memory blacklist. Expires in ${expirationTime} seconds.`);
    });
  });

  describe('isBlacklisted', () => {
    beforeEach(() => {
      service = new TokenBlacklistService(mockLogger, mockConfigService);
    });

    it('should return true for blacklisted token in Redis', async () => {
      const token = 'blacklisted-token';
      mockRedisInstance.connect.mockResolvedValue(undefined);
      mockRedisInstance.get.mockResolvedValue('blacklisted');

      const result = await service.isBlacklisted(token);

      expect(result).toBe(true);
      expect(mockRedisInstance.get).toHaveBeenCalledWith(token);
      expect(mockLogger.debug).toHaveBeenCalledWith(`Checking Redis blacklist for token ${token}: blacklisted`);
    });

    it('should return false for non-blacklisted token in Redis', async () => {
      const token = 'valid-token';
      mockRedisInstance.connect.mockResolvedValue(undefined);
      mockRedisInstance.get.mockResolvedValue(null);

      const result = await service.isBlacklisted(token);

      expect(result).toBe(false);
      expect(mockRedisInstance.get).toHaveBeenCalledWith(token);
      expect(mockLogger.debug).toHaveBeenCalledWith(`Checking Redis blacklist for token ${token}: not blacklisted`);
    });

    it('should handle Redis get errors and fallback to in-memory', async () => {
      const token = 'test-token';
      const error = new Error('Redis get failed');
      mockRedisInstance.connect.mockResolvedValue(undefined);
      mockRedisInstance.get.mockRejectedValue(error);

      const result = await service.isBlacklisted(token);

      expect(result).toBe(false);
      expect(mockLogger.error).toHaveBeenCalledWith(`Failed to check Redis blacklist for token ${token}, falling back to in-memory`, error);
      expect(mockLogger.debug).toHaveBeenCalledWith(`Checking in-memory blacklist for token ${token}: not blacklisted`);
    });

    it('should check in-memory blacklist when Redis is disabled', async () => {
      // Create service with Redis disabled
      mockConfigService.getBoolean.mockImplementation((key: string) => {
        if (key === 'USE_REDIS_BLACKLIST') return false;
        return false;
      });

      service = new TokenBlacklistService(mockLogger, mockConfigService);

      const token = 'test-token';

      // First check - should be false
      let result = await service.isBlacklisted(token);
      expect(result).toBe(false);
      expect(mockLogger.debug).toHaveBeenCalledWith(`Checking in-memory blacklist for token ${token}: not blacklisted`);

      // Add to blacklist
      await service.addToBlacklist(token, 3600);

      // Second check - should be true
      result = await service.isBlacklisted(token);
      expect(result).toBe(true);
      expect(mockLogger.debug).toHaveBeenCalledWith(`Checking in-memory blacklist for token ${token}: blacklisted`);
    });
  });

  // Note: removeFromBlacklist method is not implemented in the service
  // Tokens are automatically removed when they expire

  describe('disconnect', () => {
    beforeEach(() => {
      service = new TokenBlacklistService(mockLogger, mockConfigService);
    });

    it('should disconnect Redis client successfully', async () => {
      mockRedisInstance.quit.mockResolvedValue('OK');

      await service.disconnect();

      expect(mockRedisInstance.quit).toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith('Redis client disconnected for token blacklist.');
    });

    it('should handle Redis disconnect errors', async () => {
      const error = new Error('Redis disconnect failed');
      mockRedisInstance.quit.mockRejectedValue(error);

      await service.disconnect();

      expect(mockLogger.error).toHaveBeenCalledWith('Error disconnecting Redis client', error);
    });

    it('should handle disconnect gracefully when Redis is disabled', async () => {
      // Create service with Redis disabled
      mockConfigService.getBoolean.mockImplementation((key: string) => {
        if (key === 'USE_REDIS_BLACKLIST') return false;
        return false;
      });

      service = new TokenBlacklistService(mockLogger, mockConfigService);

      await service.disconnect();

      // Should not throw any errors
      expect(mockLogger.error).not.toHaveBeenCalled();
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle empty token gracefully', async () => {
      service = new TokenBlacklistService(mockLogger, mockConfigService);
      mockRedisInstance.connect.mockResolvedValue(undefined);
      mockRedisInstance.setex.mockResolvedValue('OK');

      await service.addToBlacklist('', 3600);

      expect(mockRedisInstance.setex).toHaveBeenCalledWith('', 3600, 'blacklisted');
    });

    it('should handle negative expiration time', async () => {
      service = new TokenBlacklistService(mockLogger, mockConfigService);
      mockRedisInstance.connect.mockResolvedValue(undefined);
      mockRedisInstance.setex.mockResolvedValue('OK');

      await service.addToBlacklist('test-token', -100);

      expect(mockRedisInstance.setex).toHaveBeenCalledWith('test-token', -100, 'blacklisted');
    });

    it('should handle very long tokens', async () => {
      service = new TokenBlacklistService(mockLogger, mockConfigService);
      mockRedisInstance.connect.mockResolvedValue(undefined);
      mockRedisInstance.setex.mockResolvedValue('OK');

      const longToken = 'a'.repeat(10000);
      await service.addToBlacklist(longToken, 3600);

      expect(mockRedisInstance.setex).toHaveBeenCalledWith(longToken, 3600, 'blacklisted');
    });
  });

  describe('In-Memory Storage Cleanup', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should clean up expired tokens from in-memory storage', async () => {
      // Create service with Redis disabled
      mockConfigService.getBoolean.mockImplementation((key: string) => {
        if (key === 'USE_REDIS_BLACKLIST') return false;
        return false;
      });

      service = new TokenBlacklistService(mockLogger, mockConfigService);

      const expiredToken = 'expired-token';
      const validToken = 'valid-token';

      // Add tokens
      await service.addToBlacklist(expiredToken, 1); // Expires in 1 second
      await service.addToBlacklist(validToken, 3600); // Expires in 1 hour

      // Both should be blacklisted initially
      expect(await service.isBlacklisted(expiredToken)).toBe(true);
      expect(await service.isBlacklisted(validToken)).toBe(true);

      // Fast forward time by 2 seconds
      jest.advanceTimersByTime(2000);

      // Expired token should be removed, valid token should remain
      expect(await service.isBlacklisted(expiredToken)).toBe(false);
      expect(await service.isBlacklisted(validToken)).toBe(true);
    });
  });
});