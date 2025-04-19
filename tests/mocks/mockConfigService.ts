import { IConfigService } from '../../src/application/interfaces/IConfigService';

const mockConfigServiceObj: IConfigService = {
    get: jest.fn((key: string): any => {
        if (key === 'aws.cognito.userPoolId') return 'mockUserPoolId';
        if (key === 'aws.cognito.clientId') return 'mockClientId';
        if (key === 'aws.region') return 'mock-region-1';
        if (key === 'resilience.circuitBreaker.timeout') return 3000;
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
        'aws.cognito.userPoolId': 'mockUserPoolId',
        'aws.cognito.clientId': 'mockClientId',
        'aws.region': 'mock-region-1',
        'resilience.circuitBreaker.timeout': 3000,
    })),
    has: jest.fn((key: string): boolean => {
        return mockConfigServiceObj.get(key) !== undefined;
    }),
};

export const mockConfigService: IConfigService = mockConfigServiceObj;

export const resetMockConfigService = () => {
    (mockConfigService.get as jest.Mock).mockClear();
    (mockConfigService.getNumber as jest.Mock).mockClear();
    (mockConfigService.getBoolean as jest.Mock).mockClear();
    (mockConfigService.getAllConfig as jest.Mock).mockClear();
    (mockConfigService.has as jest.Mock).mockClear();

    (mockConfigService.get as jest.Mock).mockImplementation((key: string): any => {
        if (key === 'aws.cognito.userPoolId') return 'mockUserPoolId';
        if (key === 'aws.cognito.clientId') return 'mockClientId';
        if (key === 'aws.region') return 'mock-region-1';
        if (key === 'resilience.circuitBreaker.timeout') return 3000;
        return undefined;
    });
    (mockConfigService.getNumber as jest.Mock).mockImplementation((key: string, defaultValue?: number): number | undefined => {
        const value = mockConfigService.get(key);
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
        'aws.cognito.userPoolId': 'mockUserPoolId',
        'aws.cognito.clientId': 'mockClientId',
        'aws.region': 'mock-region-1',
        'resilience.circuitBreaker.timeout': 3000,
    }));
    (mockConfigService.has as jest.Mock).mockImplementation((key: string): boolean => {
        return mockConfigService.get(key) !== undefined;
    });
};