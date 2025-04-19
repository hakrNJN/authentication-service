import { ChallengeNameType } from '@aws-sdk/client-cognito-identity-provider'; // Import ChallengeNameType
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

/**
 * Error indicating that Multi-Factor Authentication is required to complete login.
 */
export class MfaRequiredError extends AuthenticationError {
    public readonly session: string;
    public readonly challengeName: ChallengeNameType;
    public readonly challengeParameters: Record<string, string>; // Include challenge parameters

    constructor(
        session: string,
        challengeName: ChallengeNameType,
        challengeParameters: Record<string, string> = {}, // Initialize as empty object
        message = 'Multi-Factor Authentication Required'
    ) {
        // Use a specific status code like 401 or a custom one if preferred by the API design
        // For simplicity, using 401 but indicating MFA requirement in the message/name.
        // Alternatively, a 202 Accepted could be used in the controller/middleware.
        super(message, 401);
        this.name = 'MfaRequiredError';
        this.session = session;
        this.challengeName = challengeName;
        this.challengeParameters = challengeParameters; // Store parameters
    }
}

