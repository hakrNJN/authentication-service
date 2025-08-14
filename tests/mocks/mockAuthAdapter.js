"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetMockAuthAdapter = exports.mockAuthAdapter = void 0;
exports.mockAuthAdapter = {
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
    adminSetPassword: jest.fn(),
};
// Function to reset the mock before each test
const resetMockAuthAdapter = () => {
    Object.values(exports.mockAuthAdapter).forEach(mockFn => mockFn.mockClear());
};
exports.resetMockAuthAdapter = resetMockAuthAdapter;
