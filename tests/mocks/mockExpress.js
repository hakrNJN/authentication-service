"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetMockExpress = exports.mockNext = exports.mockResponse = exports.mockRequest = void 0;
// Mock Express Request, Response, NextFunction
const mockRequest = (body = {}, headers = {}, params = {}, query = {}) => ({
    body,
    headers,
    params,
    query,
});
exports.mockRequest = mockRequest;
const mockResponse = () => {
    const res = {};
    res.status = jest.fn().mockReturnThis();
    res.json = jest.fn().mockReturnThis();
    res.send = jest.fn().mockReturnThis();
    res.sendStatus = jest.fn().mockReturnThis();
    res.setHeader = jest.fn().mockReturnThis();
    return res; // Cast to Response for type checking
};
exports.mockResponse = mockResponse;
exports.mockNext = jest.fn();
// Function to reset the express mocks
const resetMockExpress = () => {
    // Fix: Cast mockNext to jest.Mock to access mockClear
    exports.mockNext.mockClear();
    // If mockResponse status/json were stateful, reset them here too
};
exports.resetMockExpress = resetMockExpress;
