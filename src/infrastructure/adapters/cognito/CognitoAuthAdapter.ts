import {
    AdminResetUserPasswordCommand,
    AdminResetUserPasswordCommandInput,
    AdminSetUserPasswordCommand,
    AdminSetUserPasswordCommandInput,
    AttributeType,
    AuthFlowType,
    AuthenticationResultType,
    ChallengeNameType,
    ChangePasswordCommand,
    ChangePasswordCommandInput,
    ChangePasswordCommandOutput,
    CodeDeliveryDetailsType,
    CognitoIdentityProviderClient,
    ConfirmForgotPasswordCommand,
    ConfirmForgotPasswordCommandInput,
    ConfirmForgotPasswordCommandOutput,
    ConfirmSignUpCommand,
    ConfirmSignUpCommandInput,
    ConfirmSignUpCommandOutput,
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
    NotAuthorizedException,
    RespondToAuthChallengeCommand,
    RespondToAuthChallengeCommandInput,
    RespondToAuthChallengeCommandOutput,
    SignUpCommand,
    SignUpCommandInput,
    SignUpCommandOutput
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

    private resilientInitiateAuth: (input: InitiateAuthCommandInput) => Promise<InitiateAuthCommandOutput>;
    private resilientGetUser: (input: GetUserCommandInput) => Promise<GetUserCommandOutput>;
    private resilientSignUp: (input: SignUpCommandInput) => Promise<SignUpCommandOutput>;
    private resilientConfirmSignUp: (input: ConfirmSignUpCommandInput) => Promise<ConfirmSignUpCommandOutput>;
    private resilientGlobalSignOut: (input: GlobalSignOutCommandInput) => Promise<GlobalSignOutCommandOutput>;
    private resilientForgotPassword: (input: ForgotPasswordCommandInput) => Promise<ForgotPasswordCommandOutput>;
    private resilientConfirmForgotPassword: (input: ConfirmForgotPasswordCommandInput) => Promise<ConfirmForgotPasswordCommandOutput>;
    private resilientChangePassword: (input: ChangePasswordCommandInput) => Promise<ChangePasswordCommandOutput>;
    private resilientRespondToAuthChallenge: (input: RespondToAuthChallengeCommandInput) => Promise<RespondToAuthChallengeCommandOutput>;

    constructor(
        @inject(TYPES.ConfigService) private configService: IConfigService,
        @inject(TYPES.Logger) private logger: ILogger
    ) {
        const region = this.configService.get<string>('AWS_REGION');
        this.userPoolId = this.configService.get<string>('COGNITO_USER_POOL_ID') || '';
        this.clientId = this.configService.get<string>('COGNITO_CLIENT_ID') || '';

        if (!region || !this.userPoolId || !this.clientId) {
            throw new Error('Required AWS configuration is missing');
        }

        this.client = new CognitoIdentityProviderClient({ region });

        console.log('--- [ADAPTER] Before new CognitoIdentityProviderClient ---');
        this.client = new CognitoIdentityProviderClient({ region });
        console.log('--- [ADAPTER] After new CognitoIdentityProviderClient ---');
        console.log(`--- [ADAPTER] this.client type: ${this.client?.constructor?.name}`); // See if it's the mock
        console.log(`--- [ADAPTER] typeof this.client.send: ${typeof this.client?.send}`); // *** THIS IS THE CRITICAL CHECK ***
        if (typeof this.client?.send !== 'function') {
             console.error("--- [ADAPTER] FATAL: this.client.send IS NOT A FUNCTION HERE ---", this.client);
             // You could even throw here during tests to make it fail earlier
             // throw new Error("TEST SETUP FAILED: Mock client 'send' not found in constructor");
        }

        this.logger.info('Cognito Adapter initialized.');

        // Initialize resilient functions without using bind
        this.resilientInitiateAuth = applyCircuitBreaker((i) => this.client.send(new InitiateAuthCommand(i)), 'cognito', this.logger);
        this.resilientGetUser = applyCircuitBreaker((i) => this.client.send(new GetUserCommand(i)), 'cognito', this.logger);
        this.resilientSignUp = applyCircuitBreaker((i) => this.client.send(new SignUpCommand(i)), 'cognito', this.logger);
        this.resilientConfirmSignUp = applyCircuitBreaker((i) => this.client.send(new ConfirmSignUpCommand(i)), 'cognito', this.logger);
        this.resilientGlobalSignOut = applyCircuitBreaker((i) => this.client.send(new GlobalSignOutCommand(i)), 'cognito', this.logger);
        this.resilientForgotPassword = applyCircuitBreaker((i) => this.client.send(new ForgotPasswordCommand(i)), 'cognito', this.logger);
        this.resilientConfirmForgotPassword = applyCircuitBreaker((i) => this.client.send(new ConfirmForgotPasswordCommand(i)), 'cognito', this.logger);
        this.resilientChangePassword = applyCircuitBreaker((i) => this.client.send(new ChangePasswordCommand(i)), 'cognito', this.logger);
        this.resilientRespondToAuthChallenge = applyCircuitBreaker((i) => this.client.send(new RespondToAuthChallengeCommand(i)), 'cognito', this.logger);
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
                    case ChallengeNameType.DEVICE_PASSWORD_VERIFIER:
                    case ChallengeNameType.MFA_SETUP:
                        if (!response.Session) {
                            this.logger.error(`MFA challenge received for ${username} but session is missing.`);
                            throw new AuthenticationError('MFA challenge is incomplete.');
                        }
                        throw new MfaRequiredError(
                            response.Session,
                            response.ChallengeName,
                            response.ChallengeParameters
                        );
                    default:
                        this.logger.error(`Unhandled authentication challenge for user ${username}: ${response.ChallengeName}`);
                        throw new AuthenticationError(`Unhandled authentication challenge: ${response.ChallengeName}`);
                }
            } else {
                this.logger.error(`Unexpected response during authentication for user ${username}. No auth result or challenge.`);
                throw new AuthenticationError('Unexpected authentication response.');
            }
        } catch (error: any) {
            if (error instanceof MfaRequiredError) {
                throw error;
            }
            this.handleCognitoError(error, `Authentication failed for user: ${username}`);
            throw new AuthenticationError('Authentication failed due to an unexpected error.');
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
            const response: RespondToAuthChallengeCommandOutput = await this.resilientRespondToAuthChallenge(params);

            if (response.AuthenticationResult) {
                this.logger.info(`Challenge ${challengeName} successful for user: ${username}`);
                return this.mapAuthResultToTokens(response.AuthenticationResult);
            } else if (response.ChallengeName) {
                this.logger.warn(`Another challenge received after responding to ${challengeName} for user ${username}: ${response.ChallengeName}`);
                if (!response.Session) {
                    this.logger.error(`Subsequent challenge received for ${username} but session is missing.`);
                    throw new AuthenticationError('Subsequent challenge is incomplete.');
                }
                throw new MfaRequiredError(
                    response.Session,
                    response.ChallengeName as ChallengeNameType,
                    response.ChallengeParameters
                );
            } else {
                this.logger.error(`Unexpected response after responding to ${challengeName} for user ${username}. No auth result or further challenge.`);
                throw new AuthenticationError('Unexpected response after challenge.');
            }
        } catch (error: any) {
            if (error instanceof MfaRequiredError) {
                throw error;
            }
            this.handleCognitoError(error, `Responding to ${challengeName} challenge failed for user: ${username}`);
            throw new AuthenticationError(`Failed to respond to ${challengeName} challenge due to an unexpected error.`);
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
            const response: InitiateAuthCommandOutput = await this.resilientInitiateAuth(params);
            if (response.AuthenticationResult) {
                this.logger.info('Token refresh successful.');
                return this.mapAuthResultToTokens(response.AuthenticationResult);
            } else {
                this.logger.error('Token refresh failed, no AuthenticationResult received.');
                throw new AuthenticationError('Token refresh failed unexpectedly.');
            }
        } catch (error: any) {
            this.handleCognitoError(error, 'Token refresh failed');
            throw new AuthenticationError('Token refresh failed due to an unexpected error.');
        }
    }

    async getUserFromToken(accessToken: string): Promise<Record<string, any>> {
        this.logger.debug('Attempting to get user details from access token.');
        const params: GetUserCommandInput = { AccessToken: accessToken };
        try {
            const response: GetUserCommandOutput = await this.resilientGetUser(params);
            this.logger.debug(`Successfully retrieved user details for token.`);
            const attributes: Record<string, any> = {};
            response.UserAttributes?.forEach((attr: AttributeType) => {
                if (attr.Name && attr.Value) { attributes[attr.Name] = attr.Value; }
            });
            attributes['username'] = response.Username;
            return attributes;
        } catch (error: any) {
            this.handleCognitoError(error, 'Failed to get user from token');
            throw new AuthenticationError('Failed to get user from token due to an unexpected error.');
        }
    }

    async signUp(details: SignUpDetails): Promise<SignUpResult> {
        this.logger.info(`Attempting signup for username: ${details.username}`);

        const attributesList: AttributeType[] = Object.entries(details.attributes)
            .map(([key, value]) => ({ Name: key, Value: value }));

        const params: SignUpCommandInput = {
            ClientId: this.clientId,
            Username: details.username,
            Password: details.password,
            UserAttributes: attributesList,
        };

        try {
            const response: SignUpCommandOutput = await this.resilientSignUp(params);
            this.logger.info(`Signup successful for username: ${details.username}. UserSub: ${response.UserSub}`);
            return {
                userSub: response.UserSub ?? '',
                userConfirmed: response.UserConfirmed ?? false,
                codeDeliveryDetails: response.CodeDeliveryDetails,
            };
        } catch (error: any) {
            this.handleCognitoError(error, `Signup failed for username: ${details.username}`);
            throw new BaseError('SignUpError', 500, 'Signup failed due to an unexpected error.');
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
            throw new AuthenticationError('Signup confirmation failed due to an unexpected error.');
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
            throw new AuthenticationError('Sign out failed due to an unexpected error.');
        }
    }

    async initiateForgotPassword(username: string): Promise<CodeDeliveryDetailsType | undefined> {
        this.logger.info(`Initiating forgot password for username: ${username}`);
        const params: ForgotPasswordCommandInput = {
            ClientId: this.clientId,
            Username: username,
        };
        try {
            const response: ForgotPasswordCommandOutput = await this.resilientForgotPassword(params);
            this.logger.info(`Forgot password initiated successfully for ${username}. Code sent via ${response.CodeDeliveryDetails?.DeliveryMedium}`);
            return response.CodeDeliveryDetails;
        } catch (error: any) {
            this.handleCognitoError(error, `Forgot password initiation failed for ${username}`);
            throw new BaseError('ForgotPasswordError', 500, 'Forgot password initiation failed unexpectedly.');
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
            throw new BaseError('ConfirmForgotPasswordError', 500, 'Confirm forgot password failed unexpectedly.');
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
            this.handleCognitoError(error, `Password change failed`);
            if (error instanceof NotAuthorizedException) {
                throw new AuthenticationError('Incorrect previous password provided.');
            }
            throw new BaseError('ChangePasswordError', 500, 'Password change failed unexpectedly.');
        }
    }

    async adminInitiateForgotPassword(username: string): Promise<void> {
        this.logger.info(`Initiating admin password reset for user: ${username}`);
        const params: AdminResetUserPasswordCommandInput = { UserPoolId: this.userPoolId, Username: username };
        try {
            await this.client.send(new AdminResetUserPasswordCommand(params));
            this.logger.info(`Admin password reset initiated successfully for user: ${username}`);
        } catch (error: any) {
            this.handleCognitoError(error, `Admin password reset initiation failed for user: ${username}`);
            throw new BaseError('PasswordResetError', 500, 'Failed to initiate password reset.');
        }
    }

    async adminConfirmForgotPassword(username: string, confirmationCode: string, newPassword: string): Promise<void> {
        this.logger.info(`Confirming admin password reset for user: ${username}`);
        const params: AdminSetUserPasswordCommandInput = {
            UserPoolId: this.userPoolId, Username: username, Password: newPassword, Permanent: true,
        };
        try {
            this.logger.warn(`Code verification logic for adminConfirmForgotPassword is assumed to happen outside this method.`);
            await this.client.send(new AdminSetUserPasswordCommand(params));
            this.logger.info(`Admin password set successfully for user: ${username}`);
        } catch (error: any) {
            this.handleCognitoError(error, `Admin password confirmation/setting failed for user: ${username}`);
            throw new BaseError('PasswordConfirmationError', 500, 'Failed to confirm password reset.');
        }
    }

    private mapAuthResultToTokens(authResult?: AuthenticationResultType): AuthTokens {
        if (!authResult?.AccessToken || authResult?.ExpiresIn === undefined || !authResult?.TokenType) {
            this.logger.error('Incomplete AuthenticationResult received from Cognito', authResult);
            throw new AuthenticationError('Received incomplete token data from identity provider.');
        }
        return {
            accessToken: authResult.AccessToken,
            refreshToken: authResult.RefreshToken,
            idToken: authResult.IdToken,
            expiresIn: authResult.ExpiresIn,
            tokenType: authResult.TokenType,
        };
    }

    private handleCognitoError(error: any, contextMessage: string): never {
        // --- TEMPORARY LOGGING ---
        console.log('--- handleCognitoError received error ---');
        console.log('Context:', contextMessage);
        console.log('Error Name:', error?.name);
        console.log('Error Message:', error?.message);
        console.log('Full Error Object:', JSON.stringify(error, null, 2));
        console.log('--- End handleCognitoError log ---');
        // --- END TEMPORARY LOGGING ---
        this.logger.error(`${contextMessage}: ${error.name || 'UnknownError'} - ${error.message}`, { error });

        const errorName = error.name || 'UnknownError';

        switch (errorName) {
            case 'NotAuthorizedException':
                // Check if it's an invalid token error (often contains 'Access Token' in message)
                if (error.message?.includes('Access Token')) {
                    throw new InvalidTokenError(error.message);
                }
                throw new InvalidCredentialsError(error.message || 'Invalid credentials');

            case 'UserNotFoundException':
                throw new NotFoundError('User not found');

            case 'UsernameExistsException':
                throw new ValidationError('Username already exists');

            case 'AliasExistsException':
                throw new ValidationError('Email or phone number is already in use');

            case 'UserNotConfirmedException':
                throw new UserNotConfirmedError();

            case 'PasswordResetRequiredException':
                throw new PasswordResetRequiredError();

            case 'InvalidPasswordException':
                throw new ValidationError(error.message || 'Password does not meet requirements');

            case 'InvalidParameterException':
                throw new ValidationError(error.message || 'Invalid parameters provided');

            case 'CodeMismatchException':
                throw new AuthenticationError('Invalid verification code', 400);

            case 'ExpiredCodeException':
                throw new AuthenticationError('Verification code has expired', 400);

            case 'CodeDeliveryFailureException':
                throw new BaseError(
                    'CodeDeliveryError',
                    500,
                    error.message || 'Failed to deliver verification code',
                    false
                );

            case 'LimitExceededException':
            case 'TooManyRequestsException':
            case 'TooManyFailedAttemptsException':
                throw new BaseError(
                    'RateLimitError',
                    429,
                    error.message || 'Too many requests, please try again later',
                    true // isOperational = true for rate limiting
                );

            case 'ForbiddenException':
                // Often indicates an invalid access token during operations like sign-out
                throw new InvalidTokenError(error.message || 'Operation forbidden, token might be invalid');

            case 'ResourceNotFoundException':
                // This could be user pool not found, client not found etc.
                throw new NotFoundError(error.message || 'Required resource not found');

            case 'InternalErrorException':
                throw new BaseError(
                    'IdPInternalError',
                    502, // Bad Gateway might be appropriate
                    'Identity provider internal error',
                    false
                );

            default:
                // Fallback for unhandled Cognito/AWS SDK errors
                this.logger.error(`Unhandled Cognito error type: ${errorName}`, error);
                throw new BaseError(
                    'IdPError',
                    500,
                    `An unexpected identity provider error occurred: ${error.message || errorName}`,
                    false
                );
        }
    }
}


