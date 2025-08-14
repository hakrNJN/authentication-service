"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetMockAuthService = exports.mockAuthService = void 0;
exports.mockAuthService = {
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
const resetMockAuthService = () => {
    Object.values(exports.mockAuthService).forEach(mockFn => mockFn.mockClear());
};
exports.resetMockAuthService = resetMockAuthService;
