/**
 * Base class for custom operational errors within the application.
 * Operational errors are expected errors (e.g., validation failed, resource not found)
 * as opposed to programmer errors (e.g., undefined variable access).
 */
export class BaseError extends Error {
    /**
     * The HTTP status code appropriate for this error.
     */
    public readonly statusCode: number;

    /**
     * Flag indicating if this is an operational error (true) or a programmer error (false).
     * Helps the global error handler decide how to respond.
     */
    public readonly isOperational: boolean;

    /**
     * Creates an instance of BaseError.
     * @param name - The error name (e.g., 'ValidationError', 'NotFoundError').
     * @param statusCode - The HTTP status code.
     * @param message - The error message.
     * @param isOperational - Whether the error is operational (default: true).
     */
    constructor(name: string, statusCode: number, message: string, isOperational = true) {
        super(message); // Call parent constructor (Error)

        // Set properties
        this.name = name;
        this.statusCode = statusCode;
        this.isOperational = isOperational;

        // Maintains proper stack trace for where our error was thrown (only available on V8)
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }

        // Set the prototype explicitly (necessary for extending built-in classes like Error in TypeScript)
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

// --- Example Specific Errors (You would create these as needed) ---

/**
 * Example: Error for validation failures.
 */
export class ValidationError extends BaseError {
    constructor(message = 'Validation Failed', public details?: Record<string, any>) {
        super('ValidationError', 400, message, true); // 400 Bad Request
        // Optionally add validation details if needed
    }
}

/**
 * Example: Error for resource not found.
 */
export class NotFoundError extends BaseError {
    constructor(resource = 'Resource') {
        super('NotFoundError', 404, `${resource} not found.`, true); // 404 Not Found
    }
}

/**
 * Example: Error for authentication failures.
 */
export class AuthenticationError extends BaseError {
    constructor(message = 'Authentication Required') {
        super('AuthenticationError', 401, message, true); // 401 Unauthorized
    }
}

/**
 * Example: Error for authorization failures.
 */
export class AuthorizationError extends BaseError {
    constructor(message = 'Permission Denied') {
        super('AuthorizationError', 403, message, true); // 403 Forbidden
    }
}


