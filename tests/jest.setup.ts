// Jest global setup for all tests

// Load environment variables from .env.test before anything else
import * as dotenv from 'dotenv';
dotenv.config({ path: '.env.test', override: true });

// Ensure reflect-metadata is loaded for tsyringe DI
import 'reflect-metadata';
// Set test environment variables - use .env.test values if available
process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.PORT = process.env.PORT || '3002';
process.env.LOG_LEVEL = process.env.LOG_LEVEL || 'error';
process.env.AWS_REGION = process.env.AWS_REGION || 'local';
process.env.COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'local_test_pool';
process.env.COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || 'testClientId123';

// REDIS_URL is set by individual test scripts (unit uses localhost, integration/e2e use remote)
process.env.USE_REDIS_BLACKLIST = 'true';

// Mock Redis globally using jest.fn() so tests can call .mockImplementation() on it
jest.mock('ioredis', () => {
  const MockRedis = jest.fn().mockImplementation(() => ({
    on: jest.fn(),
    setex: jest.fn().mockResolvedValue('OK'),
    get: jest.fn().mockResolvedValue(null),
    call: jest.fn().mockImplementation(async (...args: any[]) => {
      if (args[0] === 'SCRIPT' && args[1] === 'LOAD') {
        return 'mock-sha-12345';
      }
      return [1, Date.now() + 60000];
    }),
    disconnect: jest.fn().mockResolvedValue(undefined),
    quit: jest.fn().mockResolvedValue('OK'),
  }));
  return MockRedis;
});

// Global mock for applyResilience module
jest.mock('../src/infrastructure/resilience/applyResilience', () => ({
  applyCircuitBreaker: jest.fn((commandFn: (...args: any[]) => Promise<any>, _circuitBreakerId: string, _logger: any) => {
    // Return a function that properly preserves this binding and forwards the AWS SDK command
    return function (this: any, input: any) {
      // Use proper binding and preserve the input command
      return commandFn.call(this, input);
    };
  })
}));

// Optionally, silence console output during tests
// Uncomment if you want to suppress logs during test runs
// jest.spyOn(console, 'log').mockImplementation(() => {});
// jest.spyOn(console, 'info').mockImplementation(() => {});
// jest.spyOn(console, 'warn').mockImplementation(() => {});
// jest.spyOn(console, 'error').mockImplementation(() => {});

// Clear all mocks before each test
beforeEach(() => {
  jest.clearAllMocks();
});

// Global cleanup for Redis connections
afterAll(async () => {
  // Give some time for async operations to complete
  await new Promise(resolve => setTimeout(resolve, 100));

  // Force close any remaining handles
  if (global.gc) {
    global.gc();
  }
});