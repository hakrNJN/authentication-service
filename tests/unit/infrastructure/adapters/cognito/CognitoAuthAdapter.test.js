"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const client_cognito_identity_provider_1 = require("@aws-sdk/client-cognito-identity-provider");
const aws_sdk_client_mock_1 = require("aws-sdk-client-mock");
const tsyringe_1 = require("tsyringe");
const domain_1 = require("../../../../../src/domain");
const CognitoAuthAdapter_1 = require("../../../../../src/infrastructure/adapters/cognito/CognitoAuthAdapter");
const BaseError_1 = require("../../../../../src/shared/errors/BaseError");
// Mock AWS SDK
const cognitoMock = (0, aws_sdk_client_mock_1.mockClient)(client_cognito_identity_provider_1.CognitoIdentityProviderClient);
// Mock dependencies
const mockConfigService = {
    get: jest.fn(),
    getNumber: jest.fn(),
    getBoolean: jest.fn(),
    getAllConfig: jest.fn(),
    has: jest.fn(),
    getOrThrow: jest.fn()
};
const mockLogger = {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn()
};
describe('CognitoAuthAdapter', () => {
    let adapter;
    beforeEach(() => {
        // Reset all mocks
        jest.clearAllMocks();
        cognitoMock.reset();
        tsyringe_1.container.clearInstances();
        // Set up the config
        mockConfigService.get.mockImplementation((key) => {
            switch (key) {
                case 'AWS_REGION': return 'us-east-1';
                case 'COGNITO_USER_POOL_ID': return 'us-east-1_testpool';
                case 'COGNITO_CLIENT_ID': return 'test-client-id';
                default: return undefined;
            }
        });
        // Set up AWS SDK mock responses first
        mockAwsSdkResponses();
        // Create adapter instance directly (not through container)
        adapter = new CognitoAuthAdapter_1.CognitoAuthAdapter(mockConfigService, mockLogger);
        // Mock the resilient functions to pass through to the AWS SDK mock
        mockResilientFunctions(adapter);
    });
    function mockResilientFunctions(adapter) {
        // Type the commands properly to match AWS SDK expectations
        const mockSend = (command) => cognitoMock.send(command);
        // Mock all resilient functions with proper command handling
        adapter.resilientInitiateAuth = (params) => mockSend(new client_cognito_identity_provider_1.InitiateAuthCommand(params));
        adapter.resilientGetUser = (params) => mockSend(new client_cognito_identity_provider_1.GetUserCommand(params));
        adapter.resilientSignUp = (params) => mockSend(new client_cognito_identity_provider_1.SignUpCommand(params));
        adapter.resilientConfirmSignUp = (params) => mockSend(new client_cognito_identity_provider_1.ConfirmSignUpCommand(params));
        adapter.resilientGlobalSignOut = (params) => mockSend(new client_cognito_identity_provider_1.GlobalSignOutCommand(params));
        adapter.resilientForgotPassword = (params) => mockSend(new client_cognito_identity_provider_1.ForgotPasswordCommand(params));
        adapter.resilientConfirmForgotPassword = (params) => mockSend(new client_cognito_identity_provider_1.ConfirmForgotPasswordCommand(params));
        adapter.resilientChangePassword = (params) => mockSend(new client_cognito_identity_provider_1.ChangePasswordCommand(params));
        adapter.resilientRespondToAuthChallenge = (params) => mockSend(new client_cognito_identity_provider_1.RespondToAuthChallengeCommand(params));
        adapter.resilientAdminResetUserPassword = (params) => mockSend(new client_cognito_identity_provider_1.AdminResetUserPasswordCommand(params));
        adapter.resilientAdminSetUserPassword = (params) => mockSend(new client_cognito_identity_provider_1.AdminSetUserPasswordCommand(params));
    }
    function mockAwsSdkResponses() {
        cognitoMock.reset();
        // Mock AWS SDK responses with proper command types
        cognitoMock.on(client_cognito_identity_provider_1.InitiateAuthCommand).resolves({
            AuthenticationResult: {
                AccessToken: 'access-token',
                RefreshToken: 'refresh-token',
                IdToken: 'id-token',
                ExpiresIn: 3600,
                TokenType: 'Bearer'
            }
        });
        cognitoMock.on(client_cognito_identity_provider_1.SignUpCommand).resolves({
            UserSub: 'user-sub-123',
            UserConfirmed: false,
            CodeDeliveryDetails: {
                Destination: 'n***@example.com',
                DeliveryMedium: client_cognito_identity_provider_1.DeliveryMediumType.EMAIL,
                AttributeName: 'email'
            }
        });
        // Mock remaining commands with their responses
        cognitoMock.on(client_cognito_identity_provider_1.ConfirmSignUpCommand).resolves({});
        cognitoMock.on(client_cognito_identity_provider_1.GlobalSignOutCommand).resolves({});
        cognitoMock.on(client_cognito_identity_provider_1.ForgotPasswordCommand).resolves({
            CodeDeliveryDetails: {
                Destination: 'u***@example.com',
                DeliveryMedium: client_cognito_identity_provider_1.DeliveryMediumType.EMAIL,
                AttributeName: 'email'
            }
        });
        cognitoMock.on(client_cognito_identity_provider_1.ConfirmForgotPasswordCommand).resolves({});
        cognitoMock.on(client_cognito_identity_provider_1.AdminResetUserPasswordCommand).resolves({});
        cognitoMock.on(client_cognito_identity_provider_1.AdminSetUserPasswordCommand).resolves({});
        cognitoMock.on(client_cognito_identity_provider_1.GetUserCommand).resolves({
            Username: 'testuser',
            UserAttributes: []
        });
        cognitoMock.on(client_cognito_identity_provider_1.ChangePasswordCommand).resolves({});
        cognitoMock.on(client_cognito_identity_provider_1.RespondToAuthChallengeCommand).resolves({
            AuthenticationResult: {
                AccessToken: 'access-token',
                RefreshToken: 'refresh-token',
                IdToken: 'id-token',
                ExpiresIn: 3600,
                TokenType: 'Bearer'
            }
        });
    }
    describe('constructor', () => {
        it('should throw error if AWS_REGION is missing', () => {
            mockConfigService.get.mockImplementation(key => key === 'AWS_REGION' ? '' : 'dummy');
            expect(() => new CognitoAuthAdapter_1.CognitoAuthAdapter(mockConfigService, mockLogger))
                .toThrow('Required AWS Cognito configuration');
        });
        it('should throw error if COGNITO_USER_POOL_ID is missing', () => {
            mockConfigService.get.mockImplementation(key => key === 'COGNITO_USER_POOL_ID' ? '' : 'dummy');
            expect(() => new CognitoAuthAdapter_1.CognitoAuthAdapter(mockConfigService, mockLogger))
                .toThrow('Required AWS Cognito configuration');
        });
        it('should throw error if COGNITO_CLIENT_ID is missing', () => {
            mockConfigService.get.mockImplementation(key => key === 'COGNITO_CLIENT_ID' ? '' : 'dummy');
            expect(() => new CognitoAuthAdapter_1.CognitoAuthAdapter(mockConfigService, mockLogger))
                .toThrow('Required AWS Cognito configuration');
        });
    });
    describe('authenticateUser', () => {
        const username = 'testuser';
        const password = 'Password123!';
        const validAuthResult = {
            AuthenticationResult: {
                AccessToken: 'access-token',
                RefreshToken: 'refresh-token',
                IdToken: 'id-token',
                ExpiresIn: 3600,
                TokenType: 'Bearer'
            }
        };
        it('should return tokens on successful authentication', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.InitiateAuthCommand).resolves(validAuthResult);
            const result = await adapter.authenticateUser(username, password);
            expect(result).toEqual({
                accessToken: 'access-token',
                refreshToken: 'refresh-token',
                idToken: 'id-token',
                expiresIn: 3600,
                tokenType: 'Bearer'
            });
            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Authentication successful'));
        });
        it('should throw PasswordResetRequiredError when password reset is required', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.InitiateAuthCommand).resolves({
                ChallengeName: client_cognito_identity_provider_1.ChallengeNameType.NEW_PASSWORD_REQUIRED
            });
            await expect(adapter.authenticateUser(username, password))
                .rejects
                .toThrow(domain_1.PasswordResetRequiredError);
        });
        it('should throw MfaRequiredError when MFA is required', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.InitiateAuthCommand).resolves({
                ChallengeName: client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA,
                Session: 'session-token',
                ChallengeParameters: {}
            });
            await expect(adapter.authenticateUser(username, password))
                .rejects
                .toThrow(domain_1.MfaRequiredError);
        });
        it('should throw InvalidCredentialsError on NotAuthorizedException', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.InitiateAuthCommand).rejects(new client_cognito_identity_provider_1.NotAuthorizedException({ message: 'Invalid username or password', $metadata: {} }));
            await expect(adapter.authenticateUser(username, password))
                .rejects
                .toThrow(domain_1.InvalidCredentialsError);
        });
        it('should throw UserNotConfirmedError when user is not confirmed', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.InitiateAuthCommand).rejects(new client_cognito_identity_provider_1.UserNotConfirmedException({ message: 'User is not confirmed', $metadata: {} }));
            await expect(adapter.authenticateUser(username, password))
                .rejects
                .toThrow(domain_1.UserNotConfirmedError);
        });
    });
    describe('refreshToken', () => {
        const refreshToken = 'valid-refresh-token';
        const validAuthResult = {
            AuthenticationResult: {
                AccessToken: 'new-access-token',
                IdToken: 'new-id-token',
                ExpiresIn: 3600,
                TokenType: 'Bearer'
            }
        };
        it('should return new tokens on successful refresh', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.InitiateAuthCommand).resolves(validAuthResult);
            const result = await adapter.refreshToken(refreshToken);
            expect(result).toEqual({
                accessToken: 'new-access-token',
                idToken: 'new-id-token',
                expiresIn: 3600,
                tokenType: 'Bearer'
            });
            expect(mockLogger.info).toHaveBeenCalledWith('Token refresh successful.');
        });
        it('should throw InvalidTokenError when refresh token is invalid', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.InitiateAuthCommand).rejects(new client_cognito_identity_provider_1.NotAuthorizedException({ message: 'Invalid refresh token', $metadata: {} }));
            await expect(adapter.refreshToken(refreshToken))
                .rejects
                .toThrow(domain_1.InvalidTokenError);
        });
    });
    describe('signUp', () => {
        const signUpDetails = {
            username: 'newuser@example.com',
            password: 'Password123!',
            attributes: {
                email: 'newuser@example.com',
                name: 'New User'
            }
        };
        it('should return signup result on successful signup', async () => {
            const mockResponse = {
                UserSub: 'user-sub-123',
                UserConfirmed: false,
                CodeDeliveryDetails: {
                    Destination: 'n***@example.com',
                    DeliveryMedium: client_cognito_identity_provider_1.DeliveryMediumType.EMAIL,
                    AttributeName: 'email'
                }
            };
            cognitoMock.on(client_cognito_identity_provider_1.SignUpCommand).resolves(mockResponse);
            const result = await adapter.signUp(signUpDetails);
            expect(result).toEqual({
                userSub: 'user-sub-123',
                userConfirmed: false,
                codeDeliveryDetails: mockResponse.CodeDeliveryDetails
            });
        });
        it('should throw ValidationError when username already exists', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.SignUpCommand).rejects(new client_cognito_identity_provider_1.UsernameExistsException({ message: 'Username already exists', $metadata: {} }));
            await expect(adapter.signUp(signUpDetails))
                .rejects
                .toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError when password policy fails', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.SignUpCommand).rejects(new client_cognito_identity_provider_1.InvalidPasswordException({ message: 'Password does not meet requirements', $metadata: {} }));
            await expect(adapter.signUp(signUpDetails))
                .rejects
                .toThrow(domain_1.ValidationError);
        });
    });
    describe('confirmSignUp', () => {
        const username = 'user@example.com';
        const code = '123456';
        it('should complete successfully with valid code', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.ConfirmSignUpCommand).resolves({});
            await adapter.confirmSignUp(username, code);
            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Signup confirmed successfully'));
        });
        it('should throw AuthenticationError when code is invalid', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.ConfirmSignUpCommand).rejects(new client_cognito_identity_provider_1.CodeMismatchException({ message: 'Invalid verification code', $metadata: {} }));
            await expect(adapter.confirmSignUp(username, code))
                .rejects
                .toThrow(domain_1.AuthenticationError);
        });
        it('should throw AuthenticationError when code is expired', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.ConfirmSignUpCommand).rejects(new client_cognito_identity_provider_1.ExpiredCodeException({ message: 'Verification code has expired', $metadata: {} }));
            await expect(adapter.confirmSignUp(username, code))
                .rejects
                .toThrow(domain_1.AuthenticationError);
        });
    });
    describe('signOut', () => {
        const accessToken = 'valid-access-token';
        it('should complete successfully', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.GlobalSignOutCommand).resolves({});
            await adapter.signOut(accessToken);
            expect(mockLogger.info).toHaveBeenCalledWith('Global sign out successful.');
        });
        it('should throw InvalidTokenError when access token is invalid', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.GlobalSignOutCommand).rejects(new client_cognito_identity_provider_1.NotAuthorizedException({ message: 'Invalid access token', $metadata: {} }));
            await expect(adapter.signOut(accessToken))
                .rejects
                .toThrow(domain_1.InvalidTokenError);
        });
    });
    describe('initiateForgotPassword', () => {
        const username = 'user@example.com';
        it('should return code delivery details on success', async () => {
            const mockDeliveryDetails = {
                Destination: 'u***@example.com',
                DeliveryMedium: 'EMAIL',
                AttributeName: 'email'
            };
            cognitoMock.on(client_cognito_identity_provider_1.ForgotPasswordCommand).resolves({ CodeDeliveryDetails: mockDeliveryDetails });
            const result = await adapter.initiateForgotPassword(username);
            expect(result).toEqual(mockDeliveryDetails);
        });
        it('should throw NotFoundError when user does not exist', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.ForgotPasswordCommand).rejects(new client_cognito_identity_provider_1.UserNotFoundException({ message: 'User does not exist', $metadata: {} }));
            await expect(adapter.initiateForgotPassword(username))
                .rejects
                .toThrow(BaseError_1.NotFoundError);
        });
        it('should throw BaseError with RateLimitError when too many requests', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.ForgotPasswordCommand).rejects(new client_cognito_identity_provider_1.LimitExceededException({ message: 'Attempt limit exceeded', $metadata: {} }));
            await expect(adapter.initiateForgotPassword(username))
                .rejects
                .toThrow(BaseError_1.BaseError);
        });
    });
    describe('confirmForgotPassword', () => {
        const username = 'user@example.com';
        const code = '123456';
        const newPassword = 'NewPassword123!';
        it('should complete successfully with valid code and password', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.ConfirmForgotPasswordCommand).resolves({});
            await adapter.confirmForgotPassword(username, code, newPassword);
            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Password successfully reset'));
        });
        it('should throw AuthenticationError when code is invalid', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.ConfirmForgotPasswordCommand).rejects(new client_cognito_identity_provider_1.CodeMismatchException({ message: 'Invalid verification code', $metadata: {} }));
            await expect(adapter.confirmForgotPassword(username, code, newPassword))
                .rejects
                .toThrow(domain_1.AuthenticationError);
        });
        it('should throw ValidationError when new password does not meet requirements', async () => {
            cognitoMock.on(client_cognito_identity_provider_1.ConfirmForgotPasswordCommand).rejects(new client_cognito_identity_provider_1.InvalidPasswordException({ message: 'Password does not meet requirements', $metadata: {} }));
            await expect(adapter.confirmForgotPassword(username, code, newPassword))
                .rejects
                .toThrow(domain_1.ValidationError);
        });
    });
    describe('adminOperations', () => {
        const username = 'user@example.com';
        const newPassword = 'NewPassword123!';
        describe('adminInitiateForgotPassword', () => {
            it('should complete successfully', async () => {
                cognitoMock.on(client_cognito_identity_provider_1.AdminResetUserPasswordCommand).resolves({});
                await adapter.adminInitiateForgotPassword(username);
                expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Admin password reset initiated successfully'));
            });
            it('should throw NotFoundError when user does not exist', async () => {
                cognitoMock.on(client_cognito_identity_provider_1.AdminResetUserPasswordCommand).rejects(new client_cognito_identity_provider_1.UserNotFoundException({ message: 'User does not exist', $metadata: {} }));
                await expect(adapter.adminInitiateForgotPassword(username))
                    .rejects
                    .toThrow(BaseError_1.NotFoundError);
            });
        });
        describe('adminSetPassword', () => {
            it('should complete successfully', async () => {
                cognitoMock.on(client_cognito_identity_provider_1.AdminSetUserPasswordCommand).resolves({});
                await adapter.adminSetPassword(username, newPassword);
                expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Admin password set successfully'));
            });
            it('should throw ValidationError when password does not meet requirements', async () => {
                cognitoMock.on(client_cognito_identity_provider_1.AdminSetUserPasswordCommand).rejects(new client_cognito_identity_provider_1.InvalidPasswordException({ message: 'Password does not meet requirements', $metadata: {} }));
                await expect(adapter.adminSetPassword(username, newPassword))
                    .rejects
                    .toThrow(domain_1.ValidationError);
            });
            it('should throw NotFoundError when user does not exist', async () => {
                cognitoMock.on(client_cognito_identity_provider_1.AdminSetUserPasswordCommand).rejects(new client_cognito_identity_provider_1.UserNotFoundException({ message: 'User does not exist', $metadata: {} }));
                await expect(adapter.adminSetPassword(username, newPassword))
                    .rejects
                    .toThrow(BaseError_1.NotFoundError);
            });
        });
    });
});
