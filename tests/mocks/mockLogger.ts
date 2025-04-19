import { ILogger } from '../../src/application/interfaces/ILogger';

export const mockLogger: jest.Mocked<ILogger> = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
};

// Function to reset the mock before each test
export const resetMockLogger = () => {
    Object.values(mockLogger).forEach(mockFn => mockFn.mockClear());
};