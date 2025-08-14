"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetMockLogger = exports.mockLogger = void 0;
exports.mockLogger = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
};
// Function to reset the mock before each test
const resetMockLogger = () => {
    Object.values(exports.mockLogger).forEach(mockFn => mockFn.mockClear());
};
exports.resetMockLogger = resetMockLogger;
