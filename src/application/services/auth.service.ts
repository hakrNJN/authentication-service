import { inject, injectable } from 'tsyringe';
import { AuthTokens, IAuthAdapter, SignUpDetails, SignUpResult } from '../interfaces/IAuthAdapter';
import { IAuthService } from '../interfaces/IAuthService';
import { IConfigService } from '../interfaces/IConfigService';
import { ILogger } from '../interfaces/ILogger';
// import { ITokenService } from '../interfaces/ITokenService'; // Uncomment if using custom tokens
import { TYPES } from '../../shared/constants/types';
// Import specific domain errors via barrel file
import { ChallengeNameType, CodeDeliveryDetailsType, LimitExceededException } from '@aws-sdk/client-cognito-identity-provider';
import { AuthenticationError, MfaRequiredError, ValidationError } from '../../domain';
import { ILogger } from '../interfaces/ILogger';
import { ITokenBlacklistService } from '../interfaces/ITokenBlacklistService';
// import { ITokenService } from '../interfaces/ITokenService'; // Uncomment if using custom tokens
import { TYPES } from '../../shared/constants/types';
// Import specific domain errors via barrel file
import { ChallengeNameType, CodeDeliveryDetailsType, LimitExceededException } from '@aws-sdk/client-cognito-identity-provider';
import { AuthenticationError, MfaRequiredError, ValidationError } from '../../domain';
import { BaseError, NotFoundError } from '../../shared/errors/BaseError';
import { decode } from 'jsonwebtoken';

@injectable()
export class AuthService implements IAuthService {

    // Note: Resilience wrappers are now applied within the CognitoAuthAdapter

    constructor(
        @inject(TYPES.Logger) private logger: ILogger,
        @inject(TYPES.ConfigService) private configService: IConfigService,
        @inject(TYPES.AuthAdapter) private authAdapter: IAuthAdapter,
        @inject(TYPES.TokenBlacklistService) private tokenBlacklistService: ITokenBlacklistService
        // @inject(TYPES.TokenService) private tokenService: ITokenService // Uncomment if needed
    ) {
        this.logger.info('AuthService initialized.');
    }

    async login(username: string, password: string): Promise<AuthTokens> {
        this.logger.info(`Login attempt for user: ${username}`);
        if (!username || !password) {
            throw new ValidationError('Username and password are required.');
        }
        try {
            const tokens = await this.authAdapter.authenticateUser(username, password);
            this.logger.info(`Login successful for user: ${username}`);
            return tokens;
        } catch (error: any) {
            // Log differently based on whether MFA is required vs other errors
            if (error instanceof MfaRequiredError) {
                this.logger.warn(`MFA required for user ${username}: ${error.challengeName}`);
                throw error; // Re-throw MfaRequiredError to be handled by middleware/controller
            } else {
                this.logger.error(`Login failed for user ${username}: ${error.message}`, error);
                // Re-throw known operational errors directly
                if (error instanceof BaseError && error.isOperational) {
                    throw error;
                }
                // Wrap unexpected errors
                throw new AuthenticationError(`Login failed: ${error.message || 'An unexpected error occurred'}`);
            }
        }
    }

    async verifyMfa(username: string, session: string, challengeName: ChallengeNameType, code: string): Promise<AuthTokens> {
        this.logger.info(`Verifying MFA challenge ${challengeName} for user: ${username}`);
        if (!username || !session || !challengeName || !code) {
            throw new ValidationError('Username, session, challenge name, and code are required for MFA verification.');
        }

        // Prepare the challenge responses based on the challenge type
        let responses: Record<string, string> = {};
        switch (challengeName) {
            case ChallengeNameType.SMS_MFA:
                responses = { SMS_MFA_CODE: code, USERNAME: username }; // Username might be needed by Cognito here
                break;
            case ChallengeNameType.SOFTWARE_TOKEN_MFA:
                responses = { SOFTWARE_TOKEN_MFA_CODE: code, USERNAME: username }; // Username might be needed
                break;
            case ChallengeNameType.DEVICE_PASSWORD_VERIFIER:
                // For FIDO2/WebAuthn, the 'code' would be a JSON string containing the authenticator assertion response.
                // We need to parse it and map it to the expected Cognito parameters.
                // This requires understanding the specific structure Cognito expects for DEVICE_PASSWORD_VERIFIER.
                // Assuming 'code' is the JSON string for now.
                try {
                    const assertionResponse = JSON.parse(code);
                    responses = {
                        USERNAME: username,
                        DEVICE_KEY: assertionResponse.id, // Or appropriate key from assertion
                        CHALLENGE_SIGNATURE: assertionResponse.response.signature,
                        TIMESTAMP: new Date().toISOString(), // Cognito might require a timestamp
                        // Add other necessary fields based on Cognito's DEVICE_PASSWORD_VERIFIER requirements
                        // e.g., authenticatorData, clientDataJSON might be needed depending on flow
                    };
                    this.logger.info('Prepared DEVICE_PASSWORD_VERIFIER responses (structure may need adjustment based on Cognito specifics).');
                } catch (parseError) {
                    this.logger.error(`Failed to parse Passkey/FIDO2 assertion response: ${parseError}`);
                    throw new ValidationError('Invalid Passkey/FIDO2 response format.');
                }
                break;
            // Add cases for other challenges like MFA_SETUP if needed
            default:
                this.logger.error(`Unsupported challenge type for verification: ${challengeName}`);
                throw new ValidationError(`Unsupported MFA challenge type: ${challengeName}`);
        }

        try {
            const tokens = await this.authAdapter.respondToAuthChallenge(username, session, challengeName, responses);
            this.logger.info(`MFA verification successful for user: ${username}`);
            return tokens;
        } catch (error: any) {
            this.logger.error(`MFA verification failed for user ${username}: ${error.message}`, error);
            // Re-throw known operational errors directly
            if (error instanceof BaseError && error.isOperational) {
                throw error;
            }
            // Wrap unexpected errors
            throw new AuthenticationError(`MFA verification failed: ${error.message || 'An unexpected error occurred'}`);
        }
    }


    async refresh(refreshToken: string): Promise<AuthTokens> {
        this.logger.info('Token refresh requested.');
        if (!refreshToken) {
            throw new ValidationError('Refresh token is required.');
        }
        try {
            const tokens = await this.authAdapter.refreshToken(refreshToken);
            this.logger.info('Token refresh successful.');
            return tokens;
        } catch (error: any) {
            this.logger.error(`Token refresh failed: ${error.message}`, error);
            if (error instanceof AuthenticationError) { // Specifically check for auth errors from adapter
                throw error;
            }
            throw new AuthenticationError(`Token refresh failed: ${error.message || 'An unexpected error occurred'}`);
        }
    }

    async getUserInfo(accessToken: string): Promise<Record<string, any>> {
        this.logger.info('Get user info requested.');
        if (!accessToken) {
            throw new ValidationError('Access token is required.');
        }
        try {
            const userInfo = await this.authAdapter.getUserFromToken(accessToken);
            this.logger.info('Get user info successful.');
            return userInfo;
        } catch (error: any) {
            this.logger.error(`Get user info failed: ${error.message}`, error);
            if (error instanceof AuthenticationError) { // Check for auth errors (like invalid token)
                throw error;
            }
            throw new AuthenticationError(`Failed to retrieve user info: ${error.message || 'An unexpected error occurred'}`);
        }
    }

    async signUp(details: SignUpDetails): Promise<SignUpResult> {
        this.logger.info(`Signup attempt for username: ${details.username}`);
        // Add more validation if needed (e.g., check attribute formats beyond basic types)
        if (!details.username || !details.password || !details.attributes?.email) {
            // Example: Ensure email is provided in attributes
            throw new ValidationError('Username, password, and email attribute are required for signup.');
        }
        try {
            const result = await this.authAdapter.signUp(details);
            this.logger.info(`Signup successful for ${details.username}. Confirmation needed: ${!result.userConfirmed}`);
            // Potentially trigger post-signup actions here (e.g., add to default group) if needed
            return result;
        } catch (error: any) {
            this.logger.error(`Signup failed for ${details.username}: ${error.message}`, error);
            if (error instanceof BaseError && error.isOperational) {
                throw error; // Re-throw known errors (like ValidationError, UsernameExistsException mapped by adapter)
            }
            throw new BaseError('SignUpError', 500, `Signup failed: ${error.message || 'An unexpected error occurred'}`);
        }
    }

    async confirmSignUp(username: string, confirmationCode: string): Promise<void> {
        this.logger.info(`Attempting signup confirmation for: ${username}`);
        if (!username || !confirmationCode) {
            throw new ValidationError('Username and confirmation code are required.');
        }
        try {
            await this.authAdapter.confirmSignUp(username, confirmationCode);
            this.logger.info(`Signup confirmed for: ${username}`);
        } catch (error: any) {
            this.logger.error(`Signup confirmation failed for ${username}: ${error.message}`, error);
            if (error instanceof AuthenticationError || error instanceof NotFoundError) {
                throw error; // Re-throw known errors
            }
            throw new AuthenticationError(`Confirmation failed: ${error.message || 'An unexpected error occurred'}`);
        }
    }

    async logout(accessToken: string): Promise<void> {
        this.logger.info(`Logout requested.`);
        if (!accessToken) {
            throw new ValidationError('Access token is required for logout.');
        }
        try {
            await this.authAdapter.logout(accessToken);

            // Decode the token to get its expiry and jti
            const decoded = decode(accessToken) as { exp?: number, jti?: string };
            if (decoded && decoded.jti && decoded.exp) {
                const expiresIn = decoded.exp - Math.floor(Date.now() / 1000); // Time until expiry in seconds
                if (expiresIn > 0) {
                    await this.tokenBlacklistService.addToBlacklist(decoded.jti, expiresIn);
                    this.logger.info(`Access token ${decoded.jti} added to blacklist.`);
                }
            }

            this.logger.info('Logout successful.');
        } catch (error: any) {
            this.logger.error(`Logout failed: ${error.message}`, error);
            if (error instanceof AuthenticationError) { // Check for auth errors (like invalid token)
                throw error;
            }
            // Don't necessarily throw a severe error if logout fails, but log it.
            // Depending on requirements, maybe just log and return success?
            // For now, re-throwing as an AuthenticationError.
            throw new AuthenticationError(`Logout failed: ${error.message || 'An unexpected error occurred'}`);
        }
    }

    async initiateForgotPassword(username: string): Promise<CodeDeliveryDetailsType | undefined> {
        this.logger.info(`Initiating forgot password process for user: ${username}`);
        if (!username) {
            throw new ValidationError('Username is required to initiate password reset.');
        }
        try {
            const deliveryDetails = await this.authAdapter.initiateForgotPassword(username);
            this.logger.info(`Forgot password initiated for ${username}.`);
            return deliveryDetails; // Return details (e.g., where code was sent)
        } catch (error: any) {
            this.logger.error(`Initiate forgot password failed for ${username}: ${error.message}`, error);
            if (error instanceof BaseError && error.isOperational) throw error;
            throw new BaseError('ForgotPasswordError', 500, `Forgot password initiation failed: ${error.message || 'An unexpected error occurred'}`);
        }
    }

    async confirmForgotPassword(username: string, confirmationCode: string, newPassword: string): Promise<void> {
        this.logger.info(`Confirming forgot password for user: ${username}`);
        if (!username || !confirmationCode || !newPassword) {
            throw new ValidationError('Username, confirmation code, and new password are required.');
        }
        // Add password policy validation here if needed (beyond Cognito's policy)
        try {
            await this.authAdapter.confirmForgotPassword(username, confirmationCode, newPassword);
            this.logger.info(`Password reset successfully for user: ${username}`);
        } catch (error: any) {
            this.logger.error(`Confirm forgot password failed for ${username}: ${error.message}`, error);
            if (error instanceof AuthenticationError || error instanceof ValidationError || error instanceof LimitExceededException) throw error; // Re-throw known operational errors
            throw new BaseError('ConfirmForgotPasswordError', 500, `Password reset confirmation failed: ${error.message || 'An unexpected error occurred'}`);
        }
    }

    async changePassword(accessToken: string, oldPassword: string, newPassword: string): Promise<void> {
        this.logger.info(`Attempting password change for authenticated user.`);
        if (!accessToken || !oldPassword || !newPassword) {
            throw new ValidationError('Access token, old password, and new password are required.');
        }
        if (oldPassword === newPassword) {
            throw new ValidationError('New password cannot be the same as the old password.');
        }
        // Add password policy validation here if needed (beyond Cognito's policy)
        try {
            await this.authAdapter.changePassword(accessToken, oldPassword, newPassword);
            this.logger.info(`Password changed successfully for the user.`);
        } catch (error: any) {
            this.logger.error(`Password change failed: ${error.message}`, error);
            if (error instanceof AuthenticationError || error instanceof ValidationError) throw error; // Re-throw known operational errors
            throw new BaseError('ChangePasswordError', 500, `Password change failed: ${error.message || 'An unexpected error occurred'}`);
        }
    }
}
