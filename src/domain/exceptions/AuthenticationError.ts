import { BaseError } from '../../shared/errors/BaseError';

/**
 * Base class for specific authentication-related errors.
 * Inherits from BaseError for consistent handling.
 */
export class AuthenticationError extends BaseError {
    constructor(message = 'Authentication Failed', statusCode = 401) {
        // 401 Unauthorized is typical, but could be overridden (e.g., 403 for confirmed but forbidden)
        super('AuthenticationError', statusCode, message, true); // isOperational = true
    }
}

// --- Specific Authentication Errors ---

export class InvalidCredentialsError extends AuthenticationError {
    constructor(message = 'Invalid username or password.') {
        super(message, 401); // 401 Unauthorized
        this.name = 'InvalidCredentialsError';
    }
}

export class TokenExpiredError extends AuthenticationError {
    constructor(tokenType = 'Token') {
        super(`${tokenType} has expired.`, 401); // 401 Unauthorized
        this.name = 'TokenExpiredError';
    }
}

export class InvalidTokenError extends AuthenticationError {
    constructor(tokenType = 'Token') {
        super(`Invalid or malformed ${tokenType}.`, 401); // 401 Unauthorized
        this.name = 'InvalidTokenError';
    }
}

export class UserNotConfirmedError extends AuthenticationError {
    constructor(message = 'User account is not confirmed.') {
        // Using 403 Forbidden might be more appropriate than 401 here,
        // as the user exists but isn't allowed access yet.
        super(message, 403);
        this.name = 'UserNotConfirmedError';
    }
}

export class PasswordResetRequiredError extends AuthenticationError {
     constructor(message = 'Password reset is required for this user.') {
        super(message, 400); // Bad Request or maybe a custom code/redirect
        this.name = 'PasswordResetRequiredError';
    }
}

// Add other specific errors as needed (e.g., MFARequiredError)

