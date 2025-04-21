import { IConfigService } from '../../src/application/interfaces/IConfigService';

// Define the mock object implementing IConfigService
const mockConfigServiceObj: IConfigService = {
    get: jest.fn((key: string): any => {
        // --- CORRECTED KEYS ---
        if (key === 'AWS_REGION') return 'mock-region-1';
        if (key === 'COGNITO_USER_POOL_ID') return 'mockUserPoolId';
        if (key === 'COGNITO_CLIENT_ID') return 'mockClientId';
        // Keep resilience key or add others if needed elsewhere
        if (key === 'resilience.circuitBreaker.timeout') return 3000;
        // --- END CORRECTIONS ---
        console.warn(`[mockConfigService] Unexpected key requested: ${key}`); // Optional: Warn on unexpected keys
        return undefined;
    }),
    getNumber: jest.fn((key: string, defaultValue?: number): number | undefined => {
        const value = mockConfigServiceObj.get(key);
        if (value === undefined) return defaultValue;
        const num = Number(value);
        return isNaN(num) ? defaultValue : num;
    }),
    getBoolean: jest.fn((key: string, defaultValue?: boolean): boolean | undefined => {
        const value = mockConfigServiceObj.get(key);
        if (value === undefined) return defaultValue;
        if (typeof value === 'string') {
            if (value.toLowerCase() === 'true' || value === '1') return true;
            if (value.toLowerCase() === 'false' || value === '0') return false;
        }
        if (typeof value === 'boolean') return value;
        return defaultValue;
    }),
    getAllConfig: jest.fn((): Record<string, any> => ({
        // --- CORRECTED KEYS ---
        AWS_REGION: 'mock-region-1',
        COGNITO_USER_POOL_ID: 'mockUserPoolId',
        COGNITO_CLIENT_ID: 'mockClientId',
        // --- END CORRECTIONS ---
        'resilience.circuitBreaker.timeout': 3000,
    })),
    has: jest.fn((key: string): boolean => {
        // Use the get method directly to check existence based on its current implementation
        return mockConfigServiceObj.get(key) !== undefined;
    }),
};

// Export the mock object typed as the interface
export const mockConfigService: IConfigService = mockConfigServiceObj;

// Function to reset the mock before each test
export const resetMockConfigService = () => {
    // Cast each function to jest.Mock to access mockClear and mockImplementation
    (mockConfigService.get as jest.Mock).mockClear();
    (mockConfigService.getNumber as jest.Mock).mockClear();
    (mockConfigService.getBoolean as jest.Mock).mockClear();
    (mockConfigService.getAllConfig as jest.Mock).mockClear();
    (mockConfigService.has as jest.Mock).mockClear();

    // Reset implementations to defaults using the CORRECTED KEYS
    (mockConfigService.get as jest.Mock).mockImplementation((key: string): any => {
         // --- CORRECTED KEYS ---
         if (key === 'AWS_REGION') return 'mock-region-1';
         if (key === 'COGNITO_USER_POOL_ID') return 'mockUserPoolId';
         if (key === 'COGNITO_CLIENT_ID') return 'mockClientId';
         // --- END CORRECTIONS ---
         if (key === 'resilience.circuitBreaker.timeout') return 3000;
         console.warn(`[mockConfigService - reset] Unexpected key requested: ${key}`);
         return undefined;
     });
     // Reset other methods if their default implementation needs restoring
     (mockConfigService.getNumber as jest.Mock).mockImplementation((key: string, defaultValue?: number): number | undefined => {
         const value = mockConfigService.get(key); // relies on the above implementation
         if (value === undefined) return defaultValue;
         const num = Number(value);
         return isNaN(num) ? defaultValue : num;
     });
    (mockConfigService.getBoolean as jest.Mock).mockImplementation((key: string, defaultValue?: boolean): boolean | undefined => {
        const value = mockConfigService.get(key);
        if (value === undefined) return defaultValue;
        if (typeof value === 'string') {
            if (value.toLowerCase() === 'true' || value === '1') return true;
            if (value.toLowerCase() === 'false' || value === '0') return false;
        }
        if (typeof value === 'boolean') return value;
        return defaultValue;
    });
    (mockConfigService.getAllConfig as jest.Mock).mockImplementation((): Record<string, any> => ({
         // --- CORRECTED KEYS ---
         AWS_REGION: 'mock-region-1',
         COGNITO_USER_POOL_ID: 'mockUserPoolId',
         COGNITO_CLIENT_ID: 'mockClientId',
         // --- END CORRECTIONS ---
        'resilience.circuitBreaker.timeout': 3000,
    }));
    (mockConfigService.has as jest.Mock).mockImplementation((key: string): boolean => {
         // Rely on the current get implementation
        return mockConfigService.get(key) !== undefined;
    });
};