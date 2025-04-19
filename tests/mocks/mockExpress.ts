import { NextFunction, Request, Response } from 'express';

// Mock Express Request, Response, NextFunction
export const mockRequest = (body: any = {}, headers: any = {}, params: any = {}, query: any = {}): Partial<Request> => ({
    body,
    headers,
    params,
    query,
});

export const mockResponse = (): Partial<Response> => {
    const res: any = {};
    res.status = jest.fn().mockReturnThis();
    res.json = jest.fn().mockReturnThis();
    res.send = jest.fn().mockReturnThis();
    res.sendStatus = jest.fn().mockReturnThis();
    res.setHeader = jest.fn().mockReturnThis();
    return res as Response; // Cast to Response for type checking
};

export const mockNext = jest.fn() as NextFunction;

// Function to reset the express mocks
export const resetMockExpress = () => {
    // Fix: Cast mockNext to jest.Mock to access mockClear
    (mockNext as jest.Mock).mockClear();
    // If mockResponse status/json were stateful, reset them here too
};