// Jest global setup for all tests

// Ensure reflect-metadata is loaded for tsyringe DI
import 'reflect-metadata';

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.PORT = '3000';
process.env.LOG_LEVEL = 'error';
process.env.AWS_REGION = 'us-east-1';
process.env.COGNITO_USER_POOL_ID = 'us-east-1_test';
process.env.COGNITO_CLIENT_ID = 'test-client-id';

// Global mock for applyResilience with proper typing
jest.mock('../src/infrastructure/resilience/applyResilience', () => ({
    applyCircuitBreaker: (fn: (...args: any[]) => Promise<any>) => {
        // Return the function as-is, effectively bypassing circuit breaker in tests
        return fn;
    },
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