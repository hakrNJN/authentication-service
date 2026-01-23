import { inject, injectable } from 'tsyringe';
import {
    CognitoIdentityProviderClient,
    InitiateAuthCommand,
    InitiateAuthCommandInput,
    InitiateAuthCommandOutput,
    AuthFlowType,
    ChallengeNameType,
    RespondToAuthChallengeCommand,
    RespondToAuthChallengeCommandInput,
    ForgotPasswordCommand,
    ForgotPasswordCommandInput,
    ConfirmForgotPasswordCommand,
    ConfirmForgotPasswordCommandInput,
    ChangePasswordCommand,
    ChangePasswordCommandInput,
    GetUserCommand,
    GetUserCommandInput,
    GlobalSignOutCommand,
    GlobalSignOutCommandInput,
    SignUpCommand,
    SignUpCommandInput,
    ConfirmSignUpCommand,
    ConfirmSignUpCommandInput,
    AdminAddUserToGroupCommand,
    NotAuthorizedException,
    UserNotFoundException,
    UsernameExistsException,
    UserNotConfirmedException,
} from "@aws-sdk/client-cognito-identity-provider";
import { IAuthStrategy, AuthMode } from '../../../application/interfaces/IAuthStrategy';
import { AuthTokens, SignUpDetails, SignUpResult } from '../../../application/interfaces/IAuthAdapter';
import { IConfigService } from '../../../application/interfaces/IConfigService';
import { ILogger } from '../../../application/interfaces/ILogger';
import { TYPES } from '../../../shared/constants/types';
import { AuthenticationError, MfaRequiredError, PasswordResetRequiredError, ValidationError, UserNotConfirmedError } from '../../../domain';
import { applyCircuitBreaker } from '../../resilience/applyResilience';
import { BaseError, NotFoundError } from '../../../shared/errors/BaseError';

@injectable()
export class CognitoAuthStrategy implements IAuthStrategy {
    private readonly client: CognitoIdentityProviderClient;
    private readonly userPoolId: string;
    private readonly clientId: string;

    private readonly resilientInitiateAuth: (input: InitiateAuthCommandInput) => Promise<InitiateAuthCommandOutput>;
    private readonly resilientRespondToAuthChallenge: (input: RespondToAuthChallengeCommandInput) => Promise<any>;

    constructor(
        @inject(TYPES.ConfigService) private configService: IConfigService,
        @inject(TYPES.Logger) private logger: ILogger
    ) {
        const region = this.configService.get<string>('AWS_REGION');
        this.userPoolId = this.configService.get<string>('COGNITO_USER_POOL_ID') || '';
        this.clientId = this.configService.get<string>('COGNITO_CLIENT_ID') || '';

        if (!region || !this.userPoolId || !this.clientId) {
            throw new Error('Required AWS Cognito configuration is missing');
        }

        this.client = new CognitoIdentityProviderClient({ region });

        const circuitBreakerId = 'cognito';
        this.resilientInitiateAuth = applyCircuitBreaker((i) => this.client.send(new InitiateAuthCommand(i)), circuitBreakerId, this.logger);
        this.resilientRespondToAuthChallenge = applyCircuitBreaker((i) => this.client.send(new RespondToAuthChallengeCommand(i)), circuitBreakerId, this.logger);
    }

    getAuthMode(): AuthMode {
        return 'CREDENTIALS';
    }

    async login(username?: string, password?: string): Promise<AuthTokens> {
        if (!username || !password) {
            throw new AuthenticationError('Username and password are required for CREDENTIALS flow.');
        }

        this.logger.info(`Attempting Login (Strategy) for user: ${username}`);
        const params: InitiateAuthCommandInput = {
            AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
            ClientId: this.clientId,
            AuthParameters: { USERNAME: username, PASSWORD: password },
        };

        try {
            const response = await this.resilientInitiateAuth(params);

            if (response.AuthenticationResult) {
                return this.mapAuthResultToTokens(response.AuthenticationResult);
            } else if (response.ChallengeName) {
                if (response.ChallengeName === ChallengeNameType.NEW_PASSWORD_REQUIRED) {
                    throw new PasswordResetRequiredError();
                }
                if (response.ChallengeName === ChallengeNameType.SMS_MFA || response.ChallengeName === ChallengeNameType.SOFTWARE_TOKEN_MFA) {
                    throw new MfaRequiredError(response.Session!, response.ChallengeName, response.ChallengeParameters);
                }
                throw new AuthenticationError(`Unhandled challenge: ${response.ChallengeName}`);
            }
            throw new AuthenticationError('Unexpected authentication response.');
        } catch (error: any) {
            if (error instanceof MfaRequiredError || error instanceof PasswordResetRequiredError) throw error;
            this.handleCognitoError(error, 'Login failed');
            throw error; // unreachable
        }
    }

    async validateToken(token: string): Promise<any> {
        // Validation for client-side tokens (not used in CREDENTIALS flow usually)
        throw new Error('validateToken not supported in CREDENTIALS mode');
    }

    async respondToAuthChallenge(username: string, session: string, challengeName: ChallengeNameType, responses: Record<string, string>): Promise<AuthTokens> {
        this.logger.info(`Responding to ${challengeName} challenge for user: ${username}`);
        const params: RespondToAuthChallengeCommandInput = {
            ClientId: this.clientId, ChallengeName: challengeName, Session: session, ChallengeResponses: responses,
        };
        try {
            const response = await this.resilientRespondToAuthChallenge(params);
            if (response.AuthenticationResult) return this.mapAuthResultToTokens(response.AuthenticationResult);
            if (response.ChallengeName) throw new MfaRequiredError(response.Session!, response.ChallengeName as ChallengeNameType, response.ChallengeParameters);
            throw new AuthenticationError('Unexpected response after challenge.');
        } catch (error: any) { this.handleCognitoError(error, 'Respond to challenge failed'); throw error; }
    }

    async refreshToken(refreshToken: string): Promise<AuthTokens> {
        try {
            const response = await this.resilientInitiateAuth({
                AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH, ClientId: this.clientId, AuthParameters: { REFRESH_TOKEN: refreshToken },
            });
            return this.mapAuthResultToTokens(response.AuthenticationResult);
        } catch (error: any) { this.handleCognitoError(error, 'Token refresh failed'); throw error; }
    }

    async getUserFromToken(accessToken: string): Promise<Record<string, any>> {
        try {
            const response = await this.client.send(new GetUserCommand({ AccessToken: accessToken }));
            const attributes: Record<string, any> = {};
            (response.UserAttributes || []).forEach(attr => { if (attr.Name && attr.Value) attributes[attr.Name] = attr.Value; });
            attributes['username'] = response.Username;
            return attributes;
        } catch (error: any) { this.handleCognitoError(error, 'Get user failed'); throw error; }
    }

    async signUp(details: SignUpDetails): Promise<SignUpResult> {
        const attributesList = Object.entries(details.attributes).map(([key, value]) => ({ Name: key, Value: value }));
        attributesList.push({ Name: 'custom:module', Value: '[]' });
        try {
            const response = await this.client.send(new SignUpCommand({
                ClientId: this.clientId, Username: details.username, Password: details.password, UserAttributes: attributesList
            }));
            // Add to group logic: kept simple here
            if (response.UserSub) {
                try {
                    await this.client.send(new AdminAddUserToGroupCommand({
                        UserPoolId: this.userPoolId, Username: details.username, GroupName: 'users'
                    }));
                } catch (e) { this.logger.error(`Failed to add user to group: ${e}`); }
            }
            return { userSub: response.UserSub!, userConfirmed: response.UserConfirmed ?? false, codeDeliveryDetails: response.CodeDeliveryDetails };
        } catch (error: any) { this.handleCognitoError(error, 'Signup failed'); throw error; }
    }

    async confirmSignUp(username: string, code: string): Promise<void> {
        try {
            await this.client.send(new ConfirmSignUpCommand({ ClientId: this.clientId, Username: username, ConfirmationCode: code }));
        } catch (error: any) { this.handleCognitoError(error, 'Confirm signup failed'); throw error; }
    }

    async signOut(accessToken: string): Promise<void> {
        try {
            await this.client.send(new GlobalSignOutCommand({ AccessToken: accessToken }));
        } catch (error: any) { this.handleCognitoError(error, 'Sign out failed'); throw error; }
    }

    async initiateForgotPassword(username: string): Promise<any> {
        const command = new ForgotPasswordCommand({ ClientId: this.clientId, Username: username });
        try {
            const response = await this.client.send(command);
            return response.CodeDeliveryDetails;
        } catch (e) { this.handleCognitoError(e, 'Initiate forgot password failed'); throw e; }
    }

    async confirmForgotPassword(username: string, code: string, newPass: string): Promise<void> {
        const command = new ConfirmForgotPasswordCommand({
            ClientId: this.clientId, Username: username, ConfirmationCode: code, Password: newPass
        });
        try { await this.client.send(command); } catch (e) { this.handleCognitoError(e, 'Confirm forgot password failed'); throw e; }
    }

    async changePassword(accessToken: string, oldPass: string, newPass: string): Promise<void> {
        const command = new ChangePasswordCommand({
            AccessToken: accessToken, PreviousPassword: oldPass, ProposedPassword: newPass
        });
        try { await this.client.send(command); } catch (e) { this.handleCognitoError(e, 'Change password failed'); throw e; }
    }

    private mapAuthResultToTokens(result: any): AuthTokens {
        return {
            accessToken: result.AccessToken,
            refreshToken: result.RefreshToken,
            idToken: result.IdToken,
            expiresIn: result.ExpiresIn,
            tokenType: result.TokenType
        };
    }

    private handleCognitoError(error: any, context: string) {
        this.logger.error(`${context}: ${error.message}`);
        const name = error.name || 'UnknownError';

        switch (name) {
            case 'NotAuthorizedException':
            case 'InvalidParameterException':
                throw new AuthenticationError(error.message);
            case 'UserNotFoundException':
                throw new NotFoundError('User not found');
            case 'UsernameExistsException':
                throw new ValidationError('Username already exists');
            case 'UserNotConfirmedException':
                throw new UserNotConfirmedError();
            default:
                throw new BaseError('IdPError', 500, error.message);
        }
    }
}
