import {
    AdminResetUserPasswordCommand,
    AdminResetUserPasswordCommandInput,
    AdminSetUserPasswordCommand,
    AdminSetUserPasswordCommandInput,
    AliasExistsException,
    AttributeType,
    // Import necessary types
    AuthFlowType,
    AuthenticationResultType,
    ChallengeNameType,
    ChangePasswordCommand,
    ChangePasswordCommandInput,
    ChangePasswordCommandOutput,
    CodeDeliveryDetailsType,
    CodeDeliveryFailureException,
    CodeMismatchException,
    CognitoIdentityProviderClient,
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
    // Import Command Objects
    InitiateAuthCommand,
    // Import Command Inputs
    InitiateAuthCommandInput,
    // Import Command Outputs (FIX for TS2339)
    InitiateAuthCommandOutput,
    InternalErrorException,
    InvalidParameterException,
    InvalidPasswordException,
    LimitExceededException,
    // Import specific exceptions
    NotAuthorizedException,
    PasswordResetRequiredException,
    ResourceNotFoundException,
    SignUpCommand,
    SignUpCommandInput,
    SignUpCommandOutput,
    TooManyFailedAttemptsException,
    TooManyRequestsException,
    UserNotConfirmedException,
    UserNotFoundException,
    UsernameExistsException
} from "@aws-sdk/client-cognito-identity-provider";
import { inject, injectable } from 'tsyringe';

import { AuthTokens, IAuthAdapter, SignUpDetails, SignUpResult } from '../../../application/interfaces/IAuthAdapter';
import { IConfigService } from '../../../application/interfaces/IConfigService';
import { ILogger } from '../../../application/interfaces/ILogger';
import { TYPES } from '../../../shared/constants/types';
// Import specific error types from domain index
import { AuthenticationError, InvalidCredentialsError, InvalidTokenError, PasswordResetRequiredError, UserNotConfirmedError, ValidationError } from '../../../domain';
import { BaseError, NotFoundError } from '../../../shared/errors/BaseError';
import { applyCircuitBreaker } from '../../resilience/applyResilience'; // Import resilience wrapper

@injectable()
export class CognitoAuthAdapter implements IAuthAdapter {
    private readonly client: CognitoIdentityProviderClient;
    private readonly userPoolId: string;
    private readonly clientId: string;
    // private readonly clientSecret?: string; // Uncomment if using client secret

    // --- Resilient SDK Calls ---
    // Wrap SDK calls that make network requests with circuit breakers
    // FIX: Use ...CommandOutput types for return values
    private resilientInitiateAuth: (input: InitiateAuthCommandInput) => Promise<InitiateAuthCommandOutput>;
    private resilientGetUser: (input: GetUserCommandInput) => Promise<GetUserCommandOutput>;
    private resilientSignUp: (input: SignUpCommandInput) => Promise<SignUpCommandOutput>;
    private resilientConfirmSignUp: (input: ConfirmSignUpCommandInput) => Promise<ConfirmSignUpCommandOutput>;
    private resilientGlobalSignOut: (input: GlobalSignOutCommandInput) => Promise<GlobalSignOutCommandOutput>;
    private resilientForgotPassword: (input: ForgotPasswordCommandInput) => Promise<ForgotPasswordCommandOutput>; // New
    private resilientConfirmForgotPassword: (input: ConfirmForgotPasswordCommandInput) => Promise<ConfirmForgotPasswordCommandOutput>; // New
    private resilientChangePassword: (input: ChangePasswordCommandInput) => Promise<ChangePasswordCommandOutput>; // New
    // Add wrappers for other commands as needed (Admin commands, RespondToAuthChallenge)


    constructor(
        @inject(TYPES.ConfigService) private configService: IConfigService,
        @inject(TYPES.Logger) private logger: ILogger
    ) {
        const region = this.configService.get<string>('AWS_REGION'); // Required key checked by ConfigService constructor
        this.userPoolId = this.configService.get<string>('COGNITO_USER_POOL_ID') || ''; // Required key
        this.clientId = this.configService.get<string>('COGNITO_CLIENT_ID') || ''; // Required key
        // this.clientSecret = this.configService.get<string>('COGNITO_CLIENT_SECRET'); // Uncomment if needed

        this.client = new CognitoIdentityProviderClient({ region });
        this.logger.info('Cognito Adapter initialized.');

        // Initialize resilient functions
        // Note: Binding `this.client.send` ensures the context (`this`) is correct for the SDK client.
        this.resilientInitiateAuth = applyCircuitBreaker(async (i) => this.client.send(new InitiateAuthCommand(i)), 'cognito', this.logger);
        this.resilientGetUser = applyCircuitBreaker(async (i) => this.client.send(new GetUserCommand(i)), 'cognito', this.logger);
        this.resilientSignUp = applyCircuitBreaker(async (i) => this.client.send(new SignUpCommand(i)), 'cognito', this.logger);
        this.resilientConfirmSignUp = applyCircuitBreaker(async (i) => this.client.send(new ConfirmSignUpCommand(i)), 'cognito', this.logger);
        this.resilientGlobalSignOut = applyCircuitBreaker(async (i) => this.client.send(new GlobalSignOutCommand(i)), 'cognito', this.logger);
        this.resilientForgotPassword = applyCircuitBreaker(async (i) => this.client.send(new ForgotPasswordCommand(i)), 'cognito', this.logger); // New
        this.resilientConfirmForgotPassword = applyCircuitBreaker(async (i) => this.client.send(new ConfirmForgotPasswordCommand(i)), 'cognito', this.logger); // New
        this.resilientChangePassword = applyCircuitBreaker(async (i) => this.client.send(new ChangePasswordCommand(i)), 'cognito', this.logger); // New
       // Initialize other wrappers...
    }

    async authenticateUser(username: string, password: string): Promise<AuthTokens> {
        this.logger.info(`Attempting authentication for user: ${username}`);
        const params: InitiateAuthCommandInput = {
            AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
            ClientId: this.clientId,
            AuthParameters: { USERNAME: username, PASSWORD: password },
            // Add SECRET_HASH if needed
        };
        try {
            const response: InitiateAuthCommandOutput = await this.resilientInitiateAuth(params); // Use resilient call

            if (response.AuthenticationResult) {
                this.logger.info(`Authentication successful for user: ${username}`);
                return this.mapAuthResultToTokens(response.AuthenticationResult);
            } else if (response.ChallengeName === ChallengeNameType.NEW_PASSWORD_REQUIRED) {
                this.logger.warn(`Authentication challenge for user ${username}: NEW_PASSWORD_REQUIRED`);
                throw new PasswordResetRequiredError(); // Use specific error
            } else {
                // Handle other potential challenges if necessary (e.g., MFA)
                this.logger.error(`Unhandled authentication challenge for user ${username}: ${response.ChallengeName}`);
                throw new AuthenticationError(`Unhandled authentication challenge: ${response.ChallengeName}`);
            }
        } catch (error: any) {
            this.handleCognitoError(error, `Authentication failed for user: ${username}`);
            throw new AuthenticationError('Authentication failed due to an unexpected error.'); // Fallback
        }
    }

    async refreshToken(refreshToken: string): Promise<AuthTokens> {
        this.logger.info('Attempting token refresh.');
        const params: InitiateAuthCommandInput = {
            AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
            ClientId: this.clientId,
            AuthParameters: { REFRESH_TOKEN: refreshToken },
            // Add SECRET_HASH if needed (requires username, complex for refresh flow)
        };
        try {
            const response: InitiateAuthCommandOutput = await this.resilientInitiateAuth(params); // Use resilient call
            if (response.AuthenticationResult) {
                this.logger.info('Token refresh successful.');
                return this.mapAuthResultToTokens(response.AuthenticationResult);
            } else {
                this.logger.error('Token refresh failed, no AuthenticationResult received.');
                throw new AuthenticationError('Token refresh failed unexpectedly.');
            }
        } catch (error: any) {
            this.handleCognitoError(error, 'Token refresh failed');
            throw new AuthenticationError('Token refresh failed due to an unexpected error.'); // Fallback
        }
    }

    async getUserFromToken(accessToken: string): Promise<Record<string, any>> {
        this.logger.debug('Attempting to get user details from access token.');
        const params: GetUserCommandInput = { AccessToken: accessToken };
        try {
            const response: GetUserCommandOutput = await this.resilientGetUser(params); // Use resilient call
            this.logger.debug(`Successfully retrieved user details for token.`);
            const attributes: Record<string, any> = {};
            // FIX: Explicitly type 'attr' parameter (TS7006)
            response.UserAttributes?.forEach((attr: AttributeType) => {
                if (attr.Name && attr.Value) { attributes[attr.Name] = attr.Value; }
            });
            attributes['username'] = response.Username; // Include username from response root
            return attributes;
        } catch (error: any) {
            this.handleCognitoError(error, 'Failed to get user from token');
            throw new AuthenticationError('Failed to get user from token due to an unexpected error.'); // Fallback
        }
    }

    async signUp(details: SignUpDetails): Promise<SignUpResult> {
        this.logger.info(`Attempting signup for username: ${details.username}`);

        // Convert attributes object to Cognito AttributeType array
        const attributesList: AttributeType[] = Object.entries(details.attributes)
            .map(([key, value]) => ({ Name: key, Value: value }));

        const params: SignUpCommandInput = {
            ClientId: this.clientId,
            Username: details.username,
            Password: details.password,
            UserAttributes: attributesList,
            // Add SECRET_HASH if needed
        };

        try {
            const response: SignUpCommandOutput = await this.resilientSignUp(params); // Use resilient call
            this.logger.info(`Signup successful for username: ${details.username}. UserSub: ${response.UserSub}`);
            return {
                userSub: response.UserSub ?? '', // Cognito UserSub should always be present on success
                userConfirmed: response.UserConfirmed ?? false,
                codeDeliveryDetails: response.CodeDeliveryDetails, // Use CodeDeliveryDetails directly
            };
        } catch (error: any) {
            this.handleCognitoError(error, `Signup failed for username: ${details.username}`);
            throw new BaseError('SignUpError', 500, 'Signup failed due to an unexpected error.'); // Fallback
        }
    }

    async confirmSignUp(username: string, confirmationCode: string): Promise<void> {
        this.logger.info(`Attempting signup confirmation for username: ${username}`);
        const params: ConfirmSignUpCommandInput = {
            ClientId: this.clientId,
            Username: username,
            ConfirmationCode: confirmationCode,
            // Add SECRET_HASH if needed
        };
        try {
            // No significant output needed from response here
            await this.resilientConfirmSignUp(params); // Use resilient call
            this.logger.info(`Signup confirmed successfully for username: ${username}`);
        } catch (error: any) {
            this.handleCognitoError(error, `Signup confirmation failed for username: ${username}`);
            throw new AuthenticationError('Signup confirmation failed due to an unexpected error.'); // Fallback
        }
    }

    async signOut(accessToken: string): Promise<void> {
        this.logger.info(`Attempting global sign out.`);
        const params: GlobalSignOutCommandInput = {
            AccessToken: accessToken,
        };
        try {
            // No significant output needed from response here
            await this.resilientGlobalSignOut(params); // Use resilient call
            this.logger.info(`Global sign out successful.`);
        } catch (error: any) {
            // GlobalSignOut can throw NotAuthorizedException if token is invalid/expired
            this.handleCognitoError(error, 'Global sign out failed');
            throw new AuthenticationError('Sign out failed due to an unexpected error.'); // Fallback
        }
    }


    async initiateForgotPassword(username: string): Promise<CodeDeliveryDetailsType | undefined> {
        this.logger.info(`Initiating forgot password for username: ${username}`);
        const params: ForgotPasswordCommandInput = {
            ClientId: this.clientId, // Client ID is required for ForgotPassword
            Username: username,
            // Add SECRET_HASH if needed
        };
        try {
            const response: ForgotPasswordCommandOutput = await this.resilientForgotPassword(params);
            this.logger.info(`Forgot password initiated successfully for ${username}. Code sent via ${response.CodeDeliveryDetails?.DeliveryMedium}`);
            return response.CodeDeliveryDetails;
        } catch (error: any) {
            this.handleCognitoError(error, `Forgot password initiation failed for ${username}`);
            throw new BaseError('ForgotPasswordError', 500, 'Forgot password initiation failed unexpectedly.'); // Fallback
        }
    }

    async confirmForgotPassword(username: string, confirmationCode: string, newPassword: string): Promise<void> {
        this.logger.info(`Confirming forgot password for username: ${username}`);
        const params: ConfirmForgotPasswordCommandInput = {
            ClientId: this.clientId, // Client ID is required
            Username: username,
            ConfirmationCode: confirmationCode,
            Password: newPassword,
            // Add SECRET_HASH if needed
        };
        try {
            await this.resilientConfirmForgotPassword(params);
            this.logger.info(`Password successfully reset for username: ${username}`);
        } catch (error: any) {
            this.handleCognitoError(error, `Confirm forgot password failed for ${username}`);
            throw new BaseError('ConfirmForgotPasswordError', 500, 'Confirm forgot password failed unexpectedly.'); // Fallback
        }
    }

    async changePassword(accessToken: string, previousPassword: string, proposedPassword: string): Promise<void> {
        this.logger.info(`Attempting password change for user associated with the provided token.`);
        const params: ChangePasswordCommandInput = {
            AccessToken: accessToken, // Uses the access token to identify the user
            PreviousPassword: previousPassword,
            ProposedPassword: proposedPassword,
        };
        try {
            await this.resilientChangePassword(params);
            this.logger.info(`Password changed successfully for the user.`);
        } catch (error: any) {
            this.handleCognitoError(error, `Password change failed`);
            // Specific check for NotAuthorizedException which often means wrong old password here
            if (error instanceof NotAuthorizedException) {
                throw new AuthenticationError('Incorrect previous password provided.');
            }
            throw new BaseError('ChangePasswordError', 500, 'Password change failed unexpectedly.'); // Fallback
        }
    }

    // --- Admin Methods (Implement as needed, remember to add resilience wrappers) ---
    async adminInitiateForgotPassword(username: string): Promise<void> {
        this.logger.info(`Initiating admin password reset for user: ${username}`);
        const params: AdminResetUserPasswordCommandInput = { UserPoolId: this.userPoolId, Username: username };
        try {
            // TODO: Wrap with applyCircuitBreaker if needed
            await this.client.send(new AdminResetUserPasswordCommand(params));
            this.logger.info(`Admin password reset initiated successfully for user: ${username}`);
        } catch (error: any) {
            this.handleCognitoError(error, `Admin password reset initiation failed for user: ${username}`);
            throw new BaseError('PasswordResetError', 500, 'Failed to initiate password reset.');
        }
    }

    async adminConfirmForgotPassword(username: string, confirmationCode: string, newPassword: string): Promise<void> {
        this.logger.info(`Confirming admin password reset for user: ${username}`);
        // As noted before, this often involves AdminSetUserPassword rather than a direct confirm command.
        const params: AdminSetUserPasswordCommandInput = {
            UserPoolId: this.userPoolId, Username: username, Password: newPassword, Permanent: true,
        };
        try {
            // TODO: Wrap with applyCircuitBreaker if needed
            this.logger.warn(`Code verification logic for adminConfirmForgotPassword is assumed to happen outside this method.`);
            await this.client.send(new AdminSetUserPasswordCommand(params));
            this.logger.info(`Admin password set successfully for user: ${username}`);
        } catch (error: any) {
            this.handleCognitoError(error, `Admin password confirmation/setting failed for user: ${username}`);
            throw new BaseError('PasswordConfirmationError', 500, 'Failed to confirm password reset.');
        }
    }

    // --- Helper Methods ---

    private mapAuthResultToTokens(authResult?: AuthenticationResultType): AuthTokens {
        // Ensure AuthenticationResultType is imported or defined if not directly from SDK output type
        if (!authResult?.AccessToken || authResult?.ExpiresIn === undefined || !authResult?.TokenType) {
            this.logger.error('Incomplete AuthenticationResult received from Cognito', authResult);
            throw new AuthenticationError('Received incomplete token data from identity provider.');
        }
        return {
            accessToken: authResult.AccessToken,
            refreshToken: authResult.RefreshToken, // May be undefined on refresh
            idToken: authResult.IdToken, // May be undefined depending on flow/client settings
            expiresIn: authResult.ExpiresIn,
            tokenType: authResult.TokenType,
        };
    }

    private handleCognitoError(error: any, contextMessage: string): void {
        this.logger.error(`${contextMessage}: ${error.name || 'UnknownError'} - ${error.message}`, { error });

        // Map specific Cognito exceptions to domain exceptions
        if (error instanceof UserNotFoundException) throw new NotFoundError('User');
        if (error instanceof UsernameExistsException) throw new ValidationError('Username already exists.'); // 400 Bad Request often suitable
        if (error instanceof AliasExistsException) throw new ValidationError('Email or phone number alias already exists.');
        if (error instanceof NotAuthorizedException) throw new InvalidCredentialsError(); // Usually wrong password or user status issue
        if (error instanceof UserNotConfirmedException) throw new UserNotConfirmedError();
        if (error instanceof PasswordResetRequiredException) throw new PasswordResetRequiredError();
        if (error instanceof InvalidPasswordException) throw new ValidationError(error.message || 'Password does not meet policy requirements.');
        if (error instanceof InvalidParameterException) throw new ValidationError(error.message || 'Invalid parameters provided.');
        if (error instanceof CodeMismatchException) throw new AuthenticationError('Invalid confirmation code.', 400); // 400 Bad Request
        if (error instanceof ExpiredCodeException) throw new AuthenticationError('Confirmation code has expired.', 400); // 400 Bad Request
        if (error instanceof CodeDeliveryFailureException) throw new BaseError('CodeDeliveryError', 500, error.message || 'Failed to deliver confirmation code.', false); // Likely not operational
        if (error instanceof LimitExceededException || error instanceof TooManyRequestsException || error instanceof TooManyFailedAttemptsException) {
            throw new BaseError('RateLimitError', 429, error.message || 'Too many requests, please try again later.', true);
        }
        if (error instanceof ForbiddenException) { // Can occur in GetUser if token is invalid/revoked
            throw new InvalidTokenError();
        }
        // Add more specific mappings as needed for other Cognito exceptions...
        if (error instanceof ResourceNotFoundException) throw new NotFoundError('Resource'); // Generic not found
        if (error instanceof InternalErrorException) throw new BaseError('IdPInternalError', 502, 'Identity provider internal error.', false); // 502 Bad Gateway

        // Fallback for unhandled Cognito/AWS SDK errors
        throw new BaseError('IdPError', 500, `An unexpected error occurred with the identity provider: ${error.name || error.message}`, false); // Not operational
    }

    // Example: Calculate Secret Hash (if using client secret) - Requires 'crypto'
    /*
    private calculateSecretHash(username: string): string { ... }
    */
}
