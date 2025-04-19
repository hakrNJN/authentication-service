import { IAuthAdapter } from '../../src/application/interfaces/IAuthAdapter';

export const mockAuthAdapter: jest.Mocked<IAuthAdapter> = {
    authenticateUser: jest.fn(),
    respondToAuthChallenge: jest.fn(),
    refreshToken: jest.fn(),
    getUserFromToken: jest.fn(),
    signUp: jest.fn(),
    confirmSignUp: jest.fn(),
    signOut: jest.fn(),
    initiateForgotPassword: jest.fn(),
    confirmForgotPassword: jest.fn(),
    changePassword: jest.fn(),
    adminInitiateForgotPassword: jest.fn(),
    adminConfirmForgotPassword: jest.fn(),
};

// Function to reset the mock before each test
export const resetMockAuthAdapter = () => {
    Object.values(mockAuthAdapter).forEach(mockFn => mockFn.mockClear());
};