"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetMockConfigService = exports.mockConfigService = void 0;
// Define the mock object implementing IConfigService
const mockConfigServiceObj = {
    get: jest.fn((key) => {
        // --- CORRECTED KEYS ---
        if (key === 'AWS_REGION')
            return 'mock-region-1';
        if (key === 'COGNITO_USER_POOL_ID')
            return 'mockUserPoolId';
        if (key === 'COGNITO_CLIENT_ID')
            return 'mockClientId';
        // Keep resilience key or add others if needed elsewhere
        if (key === 'resilience.circuitBreaker.timeout')
            return 3000;
        // --- END CORRECTIONS ---
        console.warn(`[mockConfigService] Unexpected key requested: ${key}`); // Optional: Warn on unexpected keys
        return undefined;
    }),
    getNumber: jest.fn((key, defaultValue) => {
        const value = mockConfigServiceObj.get(key);
        if (value === undefined)
            return defaultValue;
        const num = Number(value);
        return isNaN(num) ? defaultValue : num;
    }),
    getBoolean: jest.fn((key, defaultValue) => {
        const value = mockConfigServiceObj.get(key);
        if (value === undefined)
            return defaultValue;
        if (typeof value === 'string') {
            if (value.toLowerCase() === 'true' || value === '1')
                return true;
            if (value.toLowerCase() === 'false' || value === '0')
                return false;
        }
        if (typeof value === 'boolean')
            return value;
        return defaultValue;
    }),
    getAllConfig: jest.fn(() => ({
        // --- CORRECTED KEYS ---
        AWS_REGION: 'mock-region-1',
        COGNITO_USER_POOL_ID: 'mockUserPoolId',
        COGNITO_CLIENT_ID: 'mockClientId',
        // --- END CORRECTIONS ---
        'resilience.circuitBreaker.timeout': 3000,
    })),
    has: jest.fn((key) => {
        // Use the get method directly to check existence based on its current implementation
        return mockConfigServiceObj.get(key) !== undefined;
    }),
    getOrThrow: jest.fn((key) => {
        const value = mockConfigServiceObj.get(key);
        if (value === undefined) {
            throw new Error(`Missing required mock configuration key: ${key}`);
        }
        return value;
    }),
};
// Export the mock object typed as the interface
exports.mockConfigService = mockConfigServiceObj;
// Function to reset the mock before each test
const resetMockConfigService = () => {
    // Cast each function to jest.Mock to access mockClear and mockImplementation
    exports.mockConfigService.get.mockClear();
    exports.mockConfigService.getNumber.mockClear();
    exports.mockConfigService.getBoolean.mockClear();
    exports.mockConfigService.getAllConfig.mockClear();
    exports.mockConfigService.has.mockClear();
    exports.mockConfigService.getOrThrow.mockClear();
    // Reset implementations to defaults using the CORRECTED KEYS
    exports.mockConfigService.get.mockImplementation((key) => {
        // --- CORRECTED KEYS ---
        if (key === 'AWS_REGION')
            return 'mock-region-1';
        if (key === 'COGNITO_USER_POOL_ID')
            return 'mockUserPoolId';
        if (key === 'COGNITO_CLIENT_ID')
            return 'mockClientId';
        // --- END CORRECTIONS ---
        if (key === 'resilience.circuitBreaker.timeout')
            return 3000;
        console.warn(`[mockConfigService - reset] Unexpected key requested: ${key}`);
        return undefined;
    });
    // Reset other methods if their default implementation needs restoring
    exports.mockConfigService.getNumber.mockImplementation((key, defaultValue) => {
        const value = exports.mockConfigService.get(key); // relies on the above implementation
        if (value === undefined)
            return defaultValue;
        const num = Number(value);
        return isNaN(num) ? defaultValue : num;
    });
    exports.mockConfigService.getBoolean.mockImplementation((key, defaultValue) => {
        const value = exports.mockConfigService.get(key); // relies on the above implementation
        if (value === undefined)
            return defaultValue;
        if (typeof value === 'string') {
            if (value.toLowerCase() === 'true' || value === '1')
                return true;
            if (value.toLowerCase() === 'false' || value === '0')
                return false;
        }
        if (typeof value === 'boolean')
            return value;
        return defaultValue;
    });
    exports.mockConfigService.getAllConfig.mockImplementation(() => ({
        // --- CORRECTED KEYS ---
        AWS_REGION: 'mock-region-1',
        COGNITO_USER_POOL_ID: 'mockUserPoolId',
        COGNITO_CLIENT_ID: 'mockClientId',
        // --- END CORRECTIONS ---
        'resilience.circuitBreaker.timeout': 3000,
    }));
    exports.mockConfigService.has.mockImplementation((key) => {
        // Rely on the current get implementation
        return exports.mockConfigService.get(key) !== undefined;
    });
    exports.mockConfigService.getOrThrow.mockImplementation((key) => {
        const value = exports.mockConfigService.get(key);
        if (value === undefined) {
            throw new Error(`Missing required mock configuration key: ${key}`);
        }
        return value;
    });
};
exports.resetMockConfigService = resetMockConfigService;
