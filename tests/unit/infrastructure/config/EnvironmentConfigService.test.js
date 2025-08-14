"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const EnvironmentConfigService_1 = require("../../../../src/infrastructure/config/EnvironmentConfigService");
// Mock console methods to prevent excessive test output
// Do this before importing/instantiating the service if it logs in constructor
let consoleInfoSpy;
let consoleErrorSpy;
let consoleDebugSpy;
let consoleWarnSpy;
beforeEach(() => {
    consoleInfoSpy = jest.spyOn(console, 'info').mockImplementation(() => { });
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => { });
    consoleDebugSpy = jest.spyOn(console, 'debug').mockImplementation(() => { });
    consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => { });
});
afterEach(() => {
    consoleInfoSpy.mockRestore();
    consoleErrorSpy.mockRestore();
    consoleDebugSpy.mockRestore();
    consoleWarnSpy.mockRestore();
});
describe('EnvironmentConfigService', () => {
    let configService;
    const originalEnv = Object.assign({}, process.env); // Deep copy to avoid interference
    // Define ALL required keys for setup
    const requiredEnvVars = {
        NODE_ENV: 'test',
        PORT: '3000',
        LOG_LEVEL: 'info',
        AWS_REGION: 'us-east-1',
        COGNITO_USER_POOL_ID: 'test-pool',
        COGNITO_CLIENT_ID: 'test-client',
    };
    beforeEach(() => {
        // Reset process.env to a clean state + required vars before each test
        process.env = Object.assign({}, requiredEnvVars);
        // Now instantiate the service
        configService = new EnvironmentConfigService_1.EnvironmentConfigService();
    });
    afterEach(() => {
        // Restore original environment after each test to prevent leakage
        process.env = Object.assign({}, originalEnv);
    });
    // afterAll not needed if using afterEach for restoration
    describe('constructor validation', () => {
        it('should throw an error if a required environment variable is missing', () => {
            // Delete one required var *before* instantiation
            delete process.env.PORT;
            expect(() => new EnvironmentConfigService_1.EnvironmentConfigService()).toThrow('[ConfigService] Missing or empty required environment variables: PORT');
        });
        it('should throw an error if a required environment variable is an empty string', () => {
            // Set one required var to empty string *before* instantiation
            process.env.LOG_LEVEL = '';
            expect(() => new EnvironmentConfigService_1.EnvironmentConfigService()).toThrow('[ConfigService] Missing or empty required environment variables: LOG_LEVEL');
        });
    });
    describe('get', () => {
        it('should return environment variable value when it exists', () => {
            process.env.TEST_VAR = 'test-value';
            // Re-instantiate service or call reloadConfig if needed after modifying env
            // For simplicity here, we assume tests don't modify required vars affecting constructor
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.get('TEST_VAR')).toBe('test-value');
        });
        it('should return default value when environment variable does not exist', () => {
            expect(configService.get('NON_EXISTENT_VAR', 'default')).toBe('default');
        });
        it('should return default value when environment variable is an empty string', () => {
            process.env.EMPTY_TEST_VAR = '';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.get('EMPTY_TEST_VAR', 'default-empty')).toBe('default-empty');
        });
        it('should return undefined when environment variable does not exist and no default provided', () => {
            expect(configService.get('NON_EXISTENT_VAR')).toBeUndefined();
        });
        it('should return undefined when environment variable is an empty string and no default provided', () => {
            process.env.EMPTY_TEST_VAR = '';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.get('EMPTY_TEST_VAR')).toBeUndefined();
        });
    });
    describe('getNumber', () => {
        it('should return number when environment variable is a valid number', () => {
            process.env.NUMBER_VAR = '123.45';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.getNumber('NUMBER_VAR')).toBe(123.45);
        });
        it('should return default value when environment variable is not a valid number', () => {
            process.env.INVALID_NUMBER = 'not-a-number';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.getNumber('INVALID_NUMBER', 42)).toBe(42);
        });
        it('should return default value when environment variable does not exist', () => {
            expect(configService.getNumber('NON_EXISTENT_NUMBER', 42)).toBe(42);
        });
        it('should return default value when environment variable is an empty string', () => {
            process.env.EMPTY_NUMBER_VAR = '';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.getNumber('EMPTY_NUMBER_VAR', 99)).toBe(99);
        });
        it('should throw an error when environment variable is invalid and no default provided', () => {
            process.env.INVALID_NUMBER = 'not-a-number';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            // Use a function wrapper for expect().toThrow()
            expect(() => configService.getNumber('INVALID_NUMBER')).toThrow('Configuration error: Environment variable "INVALID_NUMBER" is not a valid number ("not-a-number").');
        });
        it('should return undefined when environment variable is invalid/empty and no default provided', () => {
            process.env.EMPTY_NUMBER_VAR = '';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.getNumber('EMPTY_NUMBER_VAR')).toBeUndefined(); // Empty string returns undefined if no default
            expect(configService.getNumber('NON_EXISTENT_NUMBER')).toBeUndefined(); // Non-existent returns undefined if no default
        });
    });
    describe('getBoolean', () => {
        it.each([
            ['true', true],
            ['TRUE', true],
            ['1', true],
            ['false', false],
            ['FALSE', false],
            ['0', false],
        ])('should return %s for "%s" string value', (stringValue, expectedValue) => {
            process.env.BOOL_VAR = stringValue;
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.getBoolean('BOOL_VAR')).toBe(expectedValue);
        });
        it('should return default value when environment variable is not a valid boolean', () => {
            process.env.INVALID_BOOL = 'not-a-boolean';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.getBoolean('INVALID_BOOL', true)).toBe(true);
            expect(configService.getBoolean('INVALID_BOOL', false)).toBe(false);
        });
        it('should return default value when environment variable does not exist', () => {
            expect(configService.getBoolean('NON_EXISTENT_BOOL', false)).toBe(false);
            expect(configService.getBoolean('NON_EXISTENT_BOOL', true)).toBe(true);
        });
        it('should return default value when environment variable is an empty string', () => {
            process.env.EMPTY_BOOL_VAR = '';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.getBoolean('EMPTY_BOOL_VAR', true)).toBe(true);
        });
        it('should throw an error when environment variable is invalid and no default provided', () => {
            process.env.INVALID_BOOL = 'not-a-boolean';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(() => configService.getBoolean('INVALID_BOOL')).toThrow(`Configuration error: Environment variable "INVALID_BOOL" is not a valid boolean ("not-a-boolean"). Expected 'true', 'false', '1', or '0'.`);
        });
        it('should return undefined when environment variable is invalid/empty and no default provided', () => {
            process.env.EMPTY_BOOL_VAR = '';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.getBoolean('EMPTY_BOOL_VAR')).toBeUndefined(); // Empty returns undefined if no default
            expect(configService.getBoolean('NON_EXISTENT_BOOL')).toBeUndefined(); // Non-existent returns undefined if no default
        });
    });
    describe('getAllConfig', () => {
        it('should return non-sensitive environment variables and mask sensitive ones', () => {
            process.env.TEST_VAR1 = 'value1';
            process.env.DB_PASSWORD = 'secret-password';
            process.env.API_SECRET_KEY = 'very-secret';
            process.env.MY_TOKEN_VALUE = 'some-token';
            process.env.PUBLIC_KEY_INFO = 'abc-123'; // Should not be masked by default 'key' pattern
            configService = new EnvironmentConfigService_1.EnvironmentConfigService(); // Re-instantiate to pick up new vars
            const config = configService.getAllConfig();
            // Check non-sensitive vars (including required ones)
            expect(config).toHaveProperty('NODE_ENV', 'test');
            expect(config).toHaveProperty('PORT', '3000'); // PORT is string from process.env
            expect(config).toHaveProperty('TEST_VAR1', 'value1');
            expect(config).toHaveProperty('PUBLIC_KEY_INFO', 'abc-123');
            // Check sensitive values are masked
            expect(config).toHaveProperty('DB_PASSWORD', '********');
            expect(config).toHaveProperty('API_SECRET_KEY', '********');
            expect(config).toHaveProperty('MY_TOKEN_VALUE', '********');
            // Ensure original sensitive required vars are also masked if they match patterns
            // Example: If AWS_SECRET_ACCESS_KEY was required and added, it should be masked.
            // Assuming COGNITO_CLIENT_ID doesn't match sensitive patterns:
            expect(config).toHaveProperty('COGNITO_CLIENT_ID', 'test-client');
        });
    });
    describe('has', () => {
        it('should return true when environment variable exists', () => {
            process.env.EXISTING_VAR = 'value';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.has('EXISTING_VAR')).toBe(true);
        });
        it('should return false when environment variable does not exist', () => {
            expect(configService.has('NON_EXISTENT_VAR')).toBe(false);
        });
        it('should return true when environment variable is empty string', () => {
            // The 'has' method checks for key existence, not meaningful value.
            // An empty string means the key exists.
            process.env.EMPTY_VAR = '';
            configService = new EnvironmentConfigService_1.EnvironmentConfigService();
            expect(configService.has('EMPTY_VAR')).toBe(true); // Corrected expectation
        });
    });
    describe('reloadConfig', () => {
        it('should update config with new environment variables', () => {
            expect(configService.get('NEW_VAR')).toBeUndefined();
            process.env.NEW_VAR = 'new-value';
            configService.reloadConfig();
            expect(configService.get('NEW_VAR')).toBe('new-value');
        });
        it('should re-validate required keys after reload', () => {
            // Simulate a required key being removed from process.env after initial load
            delete process.env.PORT;
            expect(() => configService.reloadConfig()).toThrow('[ConfigService] Missing or empty required environment variables after reload: PORT');
        });
    });
});
