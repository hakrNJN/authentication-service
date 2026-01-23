import {
    AdminResetUserPasswordCommand,
    AdminResetUserPasswordCommandInput,
    AdminSetUserPasswordCommand,
    AdminSetUserPasswordCommandInput,
    AdminAddUserToGroupCommand,
    AliasExistsException,
    AttributeType,
    AuthFlowType,
    AuthenticationResultType,
    ChallengeNameType,
    ChangePasswordCommand,
    ChangePasswordCommandInput,
    ChangePasswordCommandOutput,
    CodeDeliveryDetailsType,
    CodeDeliveryFailureException,
    CodeMismatchException,
    CognitoIdentityProviderClient, // Keep this import
    ConfirmForgotPasswordCommand,
    ConfirmForgotPasswordCommandInput,
    ConfirmForgotPasswordCommandOutput,
    ConfirmSignUpCommand,
    ConfirmSignUpCommandInput,
    ConfirmSignUpCommandOutput,
    ExpiredCodeException,
    ForbiddenException,
    ForgotPasswordCommand,
    ForgotPasswordCommandInput,
    ForgotPasswordCommandOutput,
    GetUserCommand,
    GetUserCommandInput,
    GetUserCommandOutput,
    GlobalSignOutCommand,
    GlobalSignOutCommandInput,
    GlobalSignOutCommandOutput,
    InitiateAuthCommand,
    InitiateAuthCommandInput,
    InitiateAuthCommandOutput,
    InternalErrorException,
    InvalidParameterException,
    InvalidPasswordException,
    LimitExceededException,
    NotAuthorizedException,
    PasswordResetRequiredException,
    ResourceNotFoundException,
    RespondToAuthChallengeCommand,
    RespondToAuthChallengeCommandInput,
    RespondToAuthChallengeCommandOutput,
    SignUpCommand,
    SignUpCommandInput,
    SignUpCommandOutput,
    TooManyFailedAttemptsException,
    TooManyRequestsException,
    UserNotConfirmedException,
    // Import specific exceptions used in handleCognitoError
    UserNotFoundException,
    UsernameExistsException,
} from "@aws-sdk/client-cognito-identity-provider";
import { inject, injectable } from 'tsyringe';

import { AuthTokens, IAuthAdapter, SignUpDetails, SignUpResult } from '../../../application/interfaces/IAuthAdapter';
import { IConfigService } from '../../../application/interfaces/IConfigService';
import { ILogger } from '../../../application/interfaces/ILogger';
import { AuthenticationError, InvalidCredentialsError, InvalidTokenError, MfaRequiredError, PasswordResetRequiredError, UserNotConfirmedError, ValidationError } from '../../../domain';
import { TYPES } from '../../../shared/constants/types';
import { BaseError, NotFoundError } from '../../../shared/errors/BaseError';
import { applyCircuitBreaker } from '../../resilience/applyResilience';

@injectable()
export class CognitoAuthAdapter implements IAuthAdapter {
    private readonly client: CognitoIdentityProviderClient;
    private readonly userPoolId: string;
    private readonly clientId: string;

    // Resilient function wrappers
    private readonly resilientInitiateAuth: (input: InitiateAuthCommandInput) => Promise<InitiateAuthCommandOutput>;
    private readonly resilientGetUser: (input: GetUserCommandInput) => Promise<GetUserCommandOutput>;
    private readonly resilientSignUp: (input: SignUpCommandInput) => Promise<SignUpCommandOutput>;
    private readonly resilientConfirmSignUp: (input: ConfirmSignUpCommandInput) => Promise<ConfirmSignUpCommandOutput>;
    private readonly resilientGlobalSignOut: (input: GlobalSignOutCommandInput) => Promise<GlobalSignOutCommandOutput>;
    private readonly resilientForgotPassword: (input: ForgotPasswordCommandInput) => Promise<ForgotPasswordCommandOutput>;
    private readonly resilientConfirmForgotPassword: (input: ConfirmForgotPasswordCommandInput) => Promise<ConfirmForgotPasswordCommandOutput>;
    private readonly resilientChangePassword: (input: ChangePasswordCommandInput) => Promise<ChangePasswordCommandOutput>;
    private readonly resilientRespondToAuthChallenge: (input: RespondToAuthChallengeCommandInput) => Promise<RespondToAuthChallengeCommandOutput>;
    private readonly resilientAdminResetUserPassword: (input: AdminResetUserPasswordCommandInput) => Promise<void>; // Output is {}
    private readonly resilientAdminSetUserPassword: (input: AdminSetUserPasswordCommandInput) => Promise<void>; // Output is {}

    constructor(
        @inject(TYPES.ConfigService) private configService: IConfigService,
        @inject(TYPES.Logger) private logger: ILogger
    ) {
        const region = this.configService.get<string>('AWS_REGION');
        this.userPoolId = this.configService.get<string>('COGNITO_USER_POOL_ID') || '';
        this.clientId = this.configService.get<string>('COGNITO_CLIENT_ID') || '';

        // Use || '' only if empty strings are valid fallback defaults, otherwise let it be undefined and fail the check
        if (!region || !this.userPoolId || !this.clientId) {
            // Consider creating a specific ConfigurationError if needed
            throw new Error('Required AWS Cognito configuration (Region, UserPoolID, ClientID) is missing');
        }

        // Instantiate the client ONCE
        this.client = new CognitoIdentityProviderClient({ region });

        this.logger.info('Cognito Adapter initialized.');

        // Initialize resilient functions including admin ones
        const circuitBreakerId = 'cognito'; // Centralize ID
        this.resilientInitiateAuth = applyCircuitBreaker((i) => this.client.send(new InitiateAuthCommand(i)), circuitBreakerId, this.logger);
        this.resilientGetUser = applyCircuitBreaker((i) => this.client.send(new GetUserCommand(i)), circuitBreakerId, this.logger);
        this.resilientSignUp = applyCircuitBreaker((i) => this.client.send(new SignUpCommand(i)), circuitBreakerId, this.logger);
        this.resilientConfirmSignUp = applyCircuitBreaker((i) => this.client.send(new ConfirmSignUpCommand(i)), circuitBreakerId, this.logger);
        this.resilientGlobalSignOut = applyCircuitBreaker((i) => this.client.send(new GlobalSignOutCommand(i)), circuitBreakerId, this.logger);
        this.resilientForgotPassword = applyCircuitBreaker((i) => this.client.send(new ForgotPasswordCommand(i)), circuitBreakerId, this.logger);
        this.resilientConfirmForgotPassword = applyCircuitBreaker((i) => this.client.send(new ConfirmForgotPasswordCommand(i)), circuitBreakerId, this.logger);
        this.resilientChangePassword = applyCircuitBreaker((i) => this.client.send(new ChangePasswordCommand(i)), circuitBreakerId, this.logger);
        this.resilientRespondToAuthChallenge = applyCircuitBreaker((i) => this.client.send(new RespondToAuthChallengeCommand(i)), circuitBreakerId, this.logger);
        // Wrap admin commands (Note: Admin commands might have different failure modes/retry needs)
        this.resilientAdminResetUserPassword = applyCircuitBreaker(async (i) => { await this.client.send(new AdminResetUserPasswordCommand(i)); }, circuitBreakerId, this.logger);
        this.resilientAdminSetUserPassword = applyCircuitBreaker(async (i) => { await this.client.send(new AdminSetUserPasswordCommand(i)); }, circuitBreakerId, this.logger);
    }

    async authenticateUser(username: string, password: string): Promise<AuthTokens> {
        this.logger.info(`Attempting authentication for user: ${username}`);
        const params: InitiateAuthCommandInput = {
            AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
            ClientId: this.clientId,
            AuthParameters: { USERNAME: username, PASSWORD: password },
        };
        try {
            const response: InitiateAuthCommandOutput = await this.resilientInitiateAuth(params);

            if (response.AuthenticationResult) {
                this.logger.info(`Authentication successful for user: ${username}`);
                return this.mapAuthResultToTokens(response.AuthenticationResult);
            } else if (response.ChallengeName) {
                this.logger.warn(`Authentication challenge for user ${username}: ${response.ChallengeName}`);
                switch (response.ChallengeName) {
                    case ChallengeNameType.NEW_PASSWORD_REQUIRED:
                        throw new PasswordResetRequiredError();
                    case ChallengeNameType.SOFTWARE_TOKEN_MFA:
                    case ChallengeNameType.SMS_MFA:
                    // Add other MFA types as needed
                    case ChallengeNameType.MFA_SETUP: // Ensure MFA_SETUP is handled if used
                        if (!response.Session) {
                            this.logger.error(`MFA challenge received for ${username} but session is missing.`);
                            throw new AuthenticationError('MFA challenge is incomplete.');
                        }
                        throw new MfaRequiredError(
                            response.Session,
                            response.ChallengeName, // Cast might not be needed if type is inferred correctly
                            response.ChallengeParameters
                        );
                    default:
                        this.logger.error(`Unhandled authentication challenge for user ${username}: ${response.ChallengeName}`);
                        throw new AuthenticationError(`Unhandled authentication challenge: ${response.ChallengeName}`);
                }
            } else {
                // This path indicates an unexpected successful response from Cognito without AuthResult or Challenge
                this.logger.error(`Unexpected response during authentication for user ${username}. No auth result or challenge.`);
                throw new AuthenticationError('Unexpected authentication response.');
            }
        } catch (error: any) {
            // Re-throw specific application errors if they were already thrown (like MfaRequiredError)
            if (error instanceof MfaRequiredError || error instanceof PasswordResetRequiredError) {
                throw error;
            }
            // Let handleCognitoError deal with SDK/network errors and throw the appropriate application error
            this.handleCognitoError(error, `Authentication failed for user: ${username}`);
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new AuthenticationError('Authentication failed due to an unexpected error.');
        }
    }

    async respondToAuthChallenge(username: string, session: string, challengeName: ChallengeNameType, responses: Record<string, string>): Promise<AuthTokens> {
        this.logger.info(`Responding to ${challengeName} challenge for user: ${username}`);
        const params: RespondToAuthChallengeCommandInput = {
            ClientId: this.clientId,
            ChallengeName: challengeName,
            Session: session,
            ChallengeResponses: responses,
        };

        try {
            const response = await this.resilientRespondToAuthChallenge(params);

            if (response.AuthenticationResult) {
                this.logger.info(`Challenge ${challengeName} successful for user: ${username}`);
                return this.mapAuthResultToTokens(response.AuthenticationResult);
            } else if (response.ChallengeName) {
                // Handle subsequent challenges if necessary
                this.logger.warn(`Another challenge received after responding to ${challengeName} for user ${username}: ${response.ChallengeName}`);
                if (!response.Session) {
                    this.logger.error(`Subsequent challenge received for ${username} but session is missing.`);
                    throw new AuthenticationError('Subsequent challenge is incomplete.');
                }
                throw new MfaRequiredError(
                    response.Session,
                    response.ChallengeName as ChallengeNameType, // Ensure type compatibility
                    response.ChallengeParameters
                );
            } else {
                this.logger.error(`Unexpected response after responding to ${challengeName} for user ${username}. No auth result or further challenge.`);
                throw new AuthenticationError('Unexpected response after challenge.');
            }
        } catch (error: any) {
            if (error instanceof MfaRequiredError) { // Re-throw if it's already the correct type
                throw error;
            }
            this.handleCognitoError(error, `Responding to ${challengeName} challenge failed for user: ${username}`);
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new AuthenticationError(`Failed to respond to ${challengeName} challenge due to an unexpected error.`);
        }
    }

    async refreshToken(refreshToken: string): Promise<AuthTokens> {
        this.logger.info('Attempting token refresh.');
        const params: InitiateAuthCommandInput = {
            AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
            ClientId: this.clientId,
            AuthParameters: { REFRESH_TOKEN: refreshToken },
        };
        try {
            const response = await this.resilientInitiateAuth(params);
            if (response.AuthenticationResult) {
                this.logger.info('Token refresh successful.');
                // Ensure mapping handles potentially missing RefreshToken in the result
                return this.mapAuthResultToTokens(response.AuthenticationResult);
            } else {
                // Should not happen on successful refresh, but handle defensively
                this.logger.error('Token refresh failed, no AuthenticationResult received.');
                throw new AuthenticationError('Token refresh failed unexpectedly.');
            }
        } catch (error: any) {
            this.handleCognitoError(error, 'Token refresh failed');
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new AuthenticationError('Token refresh failed due to an unexpected error.');
        }
    }

    async getUserFromToken(accessToken: string): Promise<Record<string, any>> {
        this.logger.debug('Attempting to get user details from access token.');
        const params: GetUserCommandInput = { AccessToken: accessToken };
        try {
            const response = await this.resilientGetUser(params);
            this.logger.debug(`Successfully retrieved user details for token associated with username: ${response.Username}`);
            const attributes: Record<string, any> = {};
            // Use nullish coalescing for safety
            (response.UserAttributes ?? []).forEach((attr: AttributeType) => {
                // Ensure both Name and Value exist before adding
                if (attr.Name && attr.Value !== undefined) {
                    attributes[attr.Name] = attr.Value;
                }
            });
            // Explicitly add username if it's needed consistently by the application
            attributes['username'] = response.Username;
            return attributes;
        } catch (error: any) {
            this.handleCognitoError(error, 'Failed to get user from token');
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new AuthenticationError('Failed to get user from token due to an unexpected error.');
        }
    }

    async signUp(details: SignUpDetails): Promise<SignUpResult> {
        this.logger.info(`Attempting signup for username: ${details.username}`);

        const attributesList: AttributeType[] = Object.entries(details.attributes)
            .map(([key, value]) => ({ Name: key, Value: value }));

        // Add the custom:module attribute with an empty array string
        attributesList.push({ Name: 'custom:module', Value: '[]' });

        const params: SignUpCommandInput = {
            ClientId: this.clientId,
            Username: details.username,
            Password: details.password,
            UserAttributes: attributesList,
        };

        try {
            const response = await this.resilientSignUp(params);
            this.logger.info(`Signup successful for username: ${details.username}. UserSub: ${response.UserSub}`);

            // Add user to 'users' group after successful signup
            if (response.UserSub) {
                try {
                    await this.client.send(new AdminAddUserToGroupCommand({
                        UserPoolId: this.userPoolId,
                        Username: details.username,
                        GroupName: 'users', // The default group name
                    }));
                    this.logger.info(`User ${details.username} successfully added to 'users' group.`);
                } catch (groupError: any) {
                    this.logger.error(`Failed to add user ${details.username} to 'users' group: ${groupError.message}`, groupError);
                    // Decide how to handle this error:
                    // 1. Re-throw to fail signup (more strict)
                    // 2. Log and continue (less strict, user signs up but might not be in group)
                    // For now, we'll log and continue, as the primary signup was successful.
                }
            }

            return {
                userSub: response.UserSub ?? '', // Use nullish coalescing
                userConfirmed: response.UserConfirmed ?? false, // Use nullish coalescing
                codeDeliveryDetails: response.CodeDeliveryDetails,
            };
        } catch (error: any) {
            this.handleCognitoError(error, `Signup failed for username: ${details.username}`);
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new BaseError('SignUpError', 500, 'Signup failed due to an unexpected error.');
        }
    }

    async confirmSignUp(username: string, confirmationCode: string): Promise<void> {
        this.logger.info(`Attempting signup confirmation for username: ${username}`);
        const params: ConfirmSignUpCommandInput = {
            ClientId: this.clientId,
            Username: username,
            ConfirmationCode: confirmationCode,
        };
        try {
            await this.resilientConfirmSignUp(params);
            this.logger.info(`Signup confirmed successfully for username: ${username}`);
        } catch (error: any) {
            this.handleCognitoError(error, `Signup confirmation failed for username: ${username}`);
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new AuthenticationError('Signup confirmation failed due to an unexpected error.');
        }
    }

    async signOut(accessToken: string): Promise<void> {
        this.logger.info(`Attempting global sign out.`);
        const params: GlobalSignOutCommandInput = {
            AccessToken: accessToken,
        };
        try {
            await this.resilientGlobalSignOut(params);
            this.logger.info(`Global sign out successful.`);
        } catch (error: any) {
            this.handleCognitoError(error, 'Global sign out failed');
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new AuthenticationError('Sign out failed due to an unexpected error.');
        }
    }

    async initiateForgotPassword(username: string): Promise<CodeDeliveryDetailsType | undefined> {
        this.logger.info(`Initiating forgot password for username: ${username}`);
        const params: ForgotPasswordCommandInput = {
            ClientId: this.clientId,
            Username: username,
        };
        try {
            const response = await this.resilientForgotPassword(params);
            this.logger.info(`Forgot password initiated successfully for ${username}. Code sent via ${response.CodeDeliveryDetails?.DeliveryMedium ?? 'N/A'}`);
            return response.CodeDeliveryDetails;
        } catch (error: any) {
            this.handleCognitoError(error, `Forgot password initiation failed for ${username}`);
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new BaseError('ForgotPasswordError', 500, 'Forgot password initiation failed unexpectedly.');
        }
    }

    async confirmForgotPassword(username: string, confirmationCode: string, newPassword: string): Promise<void> {
        this.logger.info(`Confirming forgot password for username: ${username}`);
        const params: ConfirmForgotPasswordCommandInput = {
            ClientId: this.clientId,
            Username: username,
            ConfirmationCode: confirmationCode,
            Password: newPassword,
        };
        try {
            await this.resilientConfirmForgotPassword(params);
            this.logger.info(`Password successfully reset for username: ${username}`);
        } catch (error: any) {
            this.handleCognitoError(error, `Confirm forgot password failed for ${username}`);
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new BaseError('ConfirmForgotPasswordError', 500, 'Confirm forgot password failed unexpectedly.');
        }
    }

    async changePassword(accessToken: string, previousPassword: string, proposedPassword: string): Promise<void> {
        this.logger.info(`Attempting password change for user associated with the provided token.`);
        const params: ChangePasswordCommandInput = {
            AccessToken: accessToken,
            PreviousPassword: previousPassword,
            ProposedPassword: proposedPassword,
        };
        try {
            await this.resilientChangePassword(params);
            this.logger.info(`Password changed successfully for the user.`);
        } catch (error: any) {
            // Specific check for incorrect old password *before* generic handling
            if (error instanceof NotAuthorizedException && error.message?.toLowerCase().includes('incorrect username or password')) {
                this.logger.warn(`Password change failed for user: Incorrect previous password provided.`);
                throw new AuthenticationError('Incorrect previous password provided.');
            }
            // Let generic handler manage other NotAuthorizedException (e.g., invalid token) and other errors
            this.handleCognitoError(error, `Password change failed`);
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new BaseError('ChangePasswordError', 500, 'Password change failed unexpectedly.');
        }
    }

    async adminInitiateForgotPassword(username: string): Promise<void> {
        this.logger.info(`Initiating admin password reset for user: ${username}`);
        const params: AdminResetUserPasswordCommandInput = { UserPoolId: this.userPoolId, Username: username };
        try {
            // Use resilient wrapper
            await this.resilientAdminResetUserPassword(params);
            this.logger.info(`Admin password reset initiated successfully for user: ${username}`);
        } catch (error: any) {
            this.handleCognitoError(error, `Admin password reset initiation failed for user: ${username}`);
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new BaseError('PasswordResetError', 500, 'Failed to initiate password reset.');
        }
    }

    /**
     * Force sets a user's password as an administrator. Bypasses confirmation code.
     * REMEMBER TO UPDATE IAuthAdapter if this method signature changed.
     * @param username The username of the user.
     * @param newPassword The new password to set.
     */
    async adminSetPassword(username: string, newPassword: string): Promise<void> {
        this.logger.info(`Attempting admin password set for user: ${username}`);
        const params: AdminSetUserPasswordCommandInput = {
            UserPoolId: this.userPoolId,
            Username: username,
            Password: newPassword,
            Permanent: true, // Mark the password as permanent (user doesn't need to change on next login)
        };
        try {
            // Use resilient wrapper
            await this.resilientAdminSetUserPassword(params);
            this.logger.info(`Admin password set successfully for user: ${username}`);
        } catch (error: any) {
            this.handleCognitoError(error, `Admin password setting failed for user: ${username}`);
            // Note: The line below is unreachable because handleCognitoError always throws.
            // throw new BaseError('PasswordSetError', 500, 'Failed to set password.');
        }
    }


    private mapAuthResultToTokens(authResult?: AuthenticationResultType): AuthTokens {
        if (!authResult?.AccessToken || authResult?.ExpiresIn === undefined || !authResult?.TokenType) {
            this.logger.error('Incomplete AuthenticationResult received from Cognito', { authResult }); // Log object
            throw new AuthenticationError('Received incomplete token data from identity provider.');
        }
        // Note: RefreshToken might be null/undefined in some flows (e.g., after token refresh itself)
        return {
            accessToken: authResult.AccessToken,
            refreshToken: authResult.RefreshToken, // Can be undefined
            idToken: authResult.IdToken, // Can be undefined depending on flow/scopes
            expiresIn: authResult.ExpiresIn,
            tokenType: authResult.TokenType,
        };
    }

    private handleCognitoError(error: any, contextMessage: string): never {
        this.logger.error(`${contextMessage}: ${error.name || 'UnknownError'} - ${error.message}`, {
            errorName: error?.name,
        });

        const errorName = error.name || 'UnknownError';

        switch (errorName) {
            case NotAuthorizedException.name:
                // Check message for token-related errors first
                if (error.message?.toLowerCase().includes('token') ||
                    contextMessage.toLowerCase().includes('token')) {
                    throw new InvalidTokenError(error.message || 'Invalid token');
                }
                // Then check for password-specific message
                if (error.message?.toLowerCase().includes('incorrect password')) {
                    throw new InvalidCredentialsError('Incorrect password provided');
                }
                // Default to InvalidCredentials for other NotAuthorized scenarios
                throw new InvalidCredentialsError(error.message || 'Invalid credentials');

            case UserNotFoundException.name:
                throw new NotFoundError('User not found');

            case 'UsernameExistsException':
            case UsernameExistsException.name:
                throw new ValidationError('Username already exists');

            case AliasExistsException.name: // Added based on potential Cognito errors
                throw new ValidationError('Email or phone number is already in use');

            case UserNotConfirmedException.name:
                throw new UserNotConfirmedError();

            case PasswordResetRequiredException.name:
                throw new PasswordResetRequiredError();

            case InvalidPasswordException.name:
                throw new ValidationError(error.message || 'Password does not meet requirements');

            case InvalidParameterException.name:
                throw new ValidationError(error.message || 'Invalid parameters provided');

            case CodeMismatchException.name:
                throw new AuthenticationError('Invalid verification code', 400);

            case ExpiredCodeException.name:
                throw new AuthenticationError('Verification code has expired', 400);

            case CodeDeliveryFailureException.name:
                throw new BaseError(
                    'CodeDeliveryError',
                    500,
                    error.message || 'Failed to deliver verification code',
                    false // Not typically operational from caller's perspective
                );

            case LimitExceededException.name:
            case TooManyRequestsException.name:
            case TooManyFailedAttemptsException.name:
                throw new BaseError(
                    'RateLimitError',
                    429,
                    error.message || 'Too many requests, please try again later',
                    true // Operational - retry might help
                );

            case ForbiddenException.name:
                // Often indicates an invalid access token during operations like sign-out or token use
                throw new InvalidTokenError(error.message || 'Operation forbidden, token might be invalid or revoked');

            case ResourceNotFoundException.name:
                // Could be user pool, client, etc.
                throw new NotFoundError(error.message || 'Required resource not found');

            case InternalErrorException.name:
                throw new BaseError(
                    'IdPInternalError',
                    502, // Or 500/503 depending on context
                    'Identity provider internal error',
                    false // Typically not operational from caller's perspective
                );

            case 'NetworkingError':
            case 'TimeoutError':
                // AWS SDK v3 often uses these names for network issues
                this.logger.warn(`Cognito network error: ${errorName}`, error);
                throw new BaseError(
                    'IdPNetworkError',
                    503,
                    'Identity provider unavailable due to network issue',
                    true // Retryable
                );

            default:
                // Fallback for unhandled Cognito/AWS SDK errors
                this.logger.error(`Unhandled Cognito error type: ${errorName}`, error);
                throw new BaseError(
                    'IdPError', // Generic Identity Provider Error
                    500,
                    `An unexpected identity provider error occurred: ${error.message || errorName}`,
                    false // Assume not operational unless known otherwise
                );
        }
    }
}