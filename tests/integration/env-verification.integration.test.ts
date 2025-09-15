/**
 * Environment Variable Verification Test for Integration Tests
 * This test verifies that environment variables are properly set for integration tests
 */

describe('Integration Environment Variable Verification', () => {
  test('should have SHARED_SECRET environment variable set', () => {
    expect(process.env.SHARED_SECRET).toBeDefined();
    expect(process.env.SHARED_SECRET).not.toBe('');
    expect(process.env.SHARED_SECRET).toBe('test-shared-secret');
    console.log('SHARED_SECRET:', process.env.SHARED_SECRET);
  });

  test('should have REDIS_URL environment variable set to remote Redis', () => {
    expect(process.env.REDIS_URL).toBeDefined();
    expect(process.env.REDIS_URL).not.toBe('');
    expect(process.env.REDIS_URL).toMatch(/^redis:\/\//);
    expect(process.env.REDIS_URL).toBe('redis://192.168.2.252:6379');
    console.log('REDIS_URL:', process.env.REDIS_URL);
  });

  test('should have USE_REDIS_BLACKLIST environment variable set', () => {
    expect(process.env.USE_REDIS_BLACKLIST).toBeDefined();
    expect(process.env.USE_REDIS_BLACKLIST).toBe('true');
    console.log('USE_REDIS_BLACKLIST:', process.env.USE_REDIS_BLACKLIST);
  });

  test('should log all environment variables for verification', () => {
    console.log('Integration test environment variables:');
    console.log('SHARED_SECRET:', process.env.SHARED_SECRET);
    console.log('REDIS_URL:', process.env.REDIS_URL);
    console.log('USE_REDIS_BLACKLIST:', process.env.USE_REDIS_BLACKLIST);
    console.log('NODE_ENV:', process.env.NODE_ENV);
  });
});