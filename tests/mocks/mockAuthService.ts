import { IAuthService } from '../../src/application/interfaces/IAuthService';

export const mockAuthService: jest.Mocked<IAuthService> = {
    login: jest.fn(),
    verifyMfa: jest.fn(),
    refresh: jest.fn(),
    getUserInfo: jest.fn(),
    signUp: jest.fn(),
    confirmSignUp: jest.fn(),
    signOut: jest.fn(),
    initiateForgotPassword: jest.fn(),
    confirmForgotPassword: jest.fn(),
    changePassword: jest.fn(),
};

// Function to reset the mock before each test
export const resetMockAuthService = () => {
    Object.values(mockAuthService).forEach(mockFn => mockFn.mockClear());
};