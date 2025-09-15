import {
    AdminResetUserPasswordCommand,
    AdminSetUserPasswordCommand,
    ChallengeNameType,
    ChangePasswordCommand,
    CodeDeliveryDetailsType,
    CodeMismatchException,
    CognitoIdentityProviderClient,
    ConfirmForgotPasswordCommand,
    ConfirmSignUpCommand,
    DeliveryMediumType,
    ExpiredCodeException,
    ForgotPasswordCommand,
    GetUserCommand,
    GlobalSignOutCommand,
    InitiateAuthCommand,
    InvalidPasswordException,
    LimitExceededException,
    NotAuthorizedException,
    RespondToAuthChallengeCommand,
    SignUpCommand,
    UserNotConfirmedException,
    UserNotFoundException,
    UsernameExistsException
} from '@aws-sdk/client-cognito-identity-provider';
import { mockClient } from 'aws-sdk-client-mock';
import { container } from 'tsyringe';

import { IConfigService } from '../../../../../src/application/interfaces/IConfigService';
import { ILogger } from '../../../../../src/application/interfaces/ILogger';
import { AuthenticationError, InvalidCredentialsError, InvalidTokenError, MfaRequiredError, PasswordResetRequiredError, UserNotConfirmedError, ValidationError } from '../../../../../src/domain';
import { CognitoAuthAdapter } from '../../../../../src/infrastructure/adapters/cognito/CognitoAuthAdapter';
import { BaseError, NotFoundError } from '../../../../../src/shared/errors/BaseError';

// Mock AWS SDK
const cognitoMock = mockClient(CognitoIdentityProviderClient);

// Mock dependencies
const mockConfigService: jest.Mocked<IConfigService> = {
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
} as jest.Mocked<ILogger>;

describe('CognitoAuthAdapter', () => {
    let adapter: CognitoAuthAdapter;

    beforeEach(() => {
        // Reset all mocks
        jest.clearAllMocks();
        cognitoMock.reset();
        container.clearInstances();

        // Set up the config
        mockConfigService.get.mockImplementation((key: string) => {
            switch (key) {
                case 'AWS_REGION': return 'us-east-1';
                case 'COGNITO_USER_POOL_ID': return 'us-east-1_testpool';
                case 'COGNITO_CLIENT_ID': return 'testClientId123';
                default: return undefined;
            }
        });

        // Set up AWS SDK mock responses first
        mockAwsSdkResponses();

        // Create adapter instance directly (not through container)
        adapter = new CognitoAuthAdapter(mockConfigService, mockLogger);

        // Mock the resilient functions to pass through to the AWS SDK mock
        mockResilientFunctions(adapter);
    });

    function mockResilientFunctions(adapter: any) {
        // Type the commands properly to match AWS SDK expectations
        const mockSend = <T>(command: T) => cognitoMock.send(command as any);

        // Mock all resilient functions with proper command handling
        adapter.resilientInitiateAuth = (params: any) => mockSend(new InitiateAuthCommand(params));
        adapter.resilientGetUser = (params: any) => mockSend(new GetUserCommand(params));
        adapter.resilientSignUp = (params: any) => mockSend(new SignUpCommand(params));
        adapter.resilientConfirmSignUp = (params: any) => mockSend(new ConfirmSignUpCommand(params));
        adapter.resilientGlobalSignOut = (params: any) => mockSend(new GlobalSignOutCommand(params));
        adapter.resilientForgotPassword = (params: any) => mockSend(new ForgotPasswordCommand(params));
        adapter.resilientConfirmForgotPassword = (params: any) => mockSend(new ConfirmForgotPasswordCommand(params));
        adapter.resilientChangePassword = (params: any) => mockSend(new ChangePasswordCommand(params));
        adapter.resilientRespondToAuthChallenge = (params: any) => mockSend(new RespondToAuthChallengeCommand(params));
        adapter.resilientAdminResetUserPassword = (params: any) => mockSend(new AdminResetUserPasswordCommand(params));
        adapter.resilientAdminSetUserPassword = (params: any) => mockSend(new AdminSetUserPasswordCommand(params));
    }

    function mockAwsSdkResponses() {
        cognitoMock.reset();

        // Mock AWS SDK responses with proper command types
        cognitoMock.on(InitiateAuthCommand).resolves({
            AuthenticationResult: {
                AccessToken: 'access-token',
                RefreshToken: 'refresh-token',
                IdToken: 'id-token',
                ExpiresIn: 3600,
                TokenType: 'Bearer'
            }
        });

        cognitoMock.on(SignUpCommand).resolves({
            UserSub: 'user-sub-123',
            UserConfirmed: false,
            CodeDeliveryDetails: {
                Destination: 'n***@example.com',
                DeliveryMedium: DeliveryMediumType.EMAIL,
                AttributeName: 'email'
            }
        });

        // Mock remaining commands with their responses
        cognitoMock.on(ConfirmSignUpCommand).resolves({});
        cognitoMock.on(GlobalSignOutCommand).resolves({});
        cognitoMock.on(ForgotPasswordCommand).resolves({
            CodeDeliveryDetails: {
                Destination: 'u***@example.com',
                DeliveryMedium: DeliveryMediumType.EMAIL,
                AttributeName: 'email'
            }
        });
        cognitoMock.on(ConfirmForgotPasswordCommand).resolves({});
        cognitoMock.on(AdminResetUserPasswordCommand).resolves({});
        cognitoMock.on(AdminSetUserPasswordCommand).resolves({});
        cognitoMock.on(GetUserCommand).resolves({
            Username: 'testuser',
            UserAttributes: []
        });
        cognitoMock.on(ChangePasswordCommand).resolves({});
        cognitoMock.on(RespondToAuthChallengeCommand).resolves({
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
            expect(() => new CognitoAuthAdapter(mockConfigService, mockLogger))
                .toThrow('Required AWS Cognito configuration');
        });

        it('should throw error if COGNITO_USER_POOL_ID is missing', () => {
            mockConfigService.get.mockImplementation(key => key === 'COGNITO_USER_POOL_ID' ? '' : 'dummy');
            expect(() => new CognitoAuthAdapter(mockConfigService, mockLogger))
                .toThrow('Required AWS Cognito configuration');
        });

        it('should throw error if COGNITO_CLIENT_ID is missing', () => {
            mockConfigService.get.mockImplementation(key => key === 'COGNITO_CLIENT_ID' ? '' : 'dummy');
            expect(() => new CognitoAuthAdapter(mockConfigService, mockLogger))
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
            cognitoMock.on(InitiateAuthCommand).resolves(validAuthResult);

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
            cognitoMock.on(InitiateAuthCommand).resolves({
                ChallengeName: ChallengeNameType.NEW_PASSWORD_REQUIRED
            });

            await expect(adapter.authenticateUser(username, password))
                .rejects
                .toThrow(PasswordResetRequiredError);
        });

        it('should throw MfaRequiredError when MFA is required', async () => {
            cognitoMock.on(InitiateAuthCommand).resolves({
                ChallengeName: ChallengeNameType.SMS_MFA,
                Session: 'session-token',
                ChallengeParameters: {}
            });

            await expect(adapter.authenticateUser(username, password))
                .rejects
                .toThrow(MfaRequiredError);
        });

        it('should throw InvalidCredentialsError on NotAuthorizedException', async () => {
            cognitoMock.on(InitiateAuthCommand).rejects(
                new NotAuthorizedException({ message: 'Invalid username or password', $metadata: {} })
            );

            await expect(adapter.authenticateUser(username, password))
                .rejects
                .toThrow(InvalidCredentialsError);
        });

        it('should throw UserNotConfirmedError when user is not confirmed', async () => {
            cognitoMock.on(InitiateAuthCommand).rejects(
                new UserNotConfirmedException({ message: 'User is not confirmed', $metadata: {} })
            );

            await expect(adapter.authenticateUser(username, password))
                .rejects
                .toThrow(UserNotConfirmedError);
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
            cognitoMock.on(InitiateAuthCommand).resolves(validAuthResult);

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
            cognitoMock.on(InitiateAuthCommand).rejects(
                new NotAuthorizedException({ message: 'Invalid refresh token', $metadata: {} })
            );

            await expect(adapter.refreshToken(refreshToken))
                .rejects
                .toThrow(InvalidTokenError);
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
                    DeliveryMedium: DeliveryMediumType.EMAIL,
                    AttributeName: 'email'
                }
            };

            cognitoMock.on(SignUpCommand).resolves(mockResponse);

            const result = await adapter.signUp(signUpDetails);

            expect(result).toEqual({
                userSub: 'user-sub-123',
                userConfirmed: false,
                codeDeliveryDetails: mockResponse.CodeDeliveryDetails
            });
        });

        it('should throw ValidationError when username already exists', async () => {
            cognitoMock.on(SignUpCommand).rejects(
                new UsernameExistsException({ message: 'Username already exists', $metadata: {} })
            );

            await expect(adapter.signUp(signUpDetails))
                .rejects
                .toThrow(ValidationError);
        });

        it('should throw ValidationError when password policy fails', async () => {
            cognitoMock.on(SignUpCommand).rejects(
                new InvalidPasswordException({ message: 'Password does not meet requirements', $metadata: {} })
            );

            await expect(adapter.signUp(signUpDetails))
                .rejects
                .toThrow(ValidationError);
        });
    });

    describe('confirmSignUp', () => {
        const username = 'user@example.com';
        const code = '123456';

        it('should complete successfully with valid code', async () => {
            cognitoMock.on(ConfirmSignUpCommand).resolves({});

            await adapter.confirmSignUp(username, code);

            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Signup confirmed successfully'));
        });

        it('should throw AuthenticationError when code is invalid', async () => {
            cognitoMock.on(ConfirmSignUpCommand).rejects(
                new CodeMismatchException({ message: 'Invalid verification code', $metadata: {} })
            );

            await expect(adapter.confirmSignUp(username, code))
                .rejects
                .toThrow(AuthenticationError);
        });

        it('should throw AuthenticationError when code is expired', async () => {
            cognitoMock.on(ConfirmSignUpCommand).rejects(
                new ExpiredCodeException({ message: 'Verification code has expired', $metadata: {} })
            );

            await expect(adapter.confirmSignUp(username, code))
                .rejects
                .toThrow(AuthenticationError);
        });
    });

    describe('signOut', () => {
        const accessToken = 'valid-access-token';

        it('should complete successfully', async () => {
            cognitoMock.on(GlobalSignOutCommand).resolves({});

            await adapter.signOut(accessToken);

            expect(mockLogger.info).toHaveBeenCalledWith('Global sign out successful.');
        });

        it('should throw InvalidTokenError when access token is invalid', async () => {
            cognitoMock.on(GlobalSignOutCommand).rejects(
                new NotAuthorizedException({ message: 'Invalid access token', $metadata: {} })
            );

            await expect(adapter.signOut(accessToken))
                .rejects
                .toThrow(InvalidTokenError);
        });
    });

    describe('initiateForgotPassword', () => {
        const username = 'user@example.com';

        it('should return code delivery details on success', async () => {
            const mockDeliveryDetails: CodeDeliveryDetailsType = {
                Destination: 'u***@example.com',
                DeliveryMedium: 'EMAIL',
                AttributeName: 'email'
            };

            cognitoMock.on(ForgotPasswordCommand).resolves({ CodeDeliveryDetails: mockDeliveryDetails });

            const result = await adapter.initiateForgotPassword(username);

            expect(result).toEqual(mockDeliveryDetails);
        });

        it('should throw NotFoundError when user does not exist', async () => {
            cognitoMock.on(ForgotPasswordCommand).rejects(
                new UserNotFoundException({ message: 'User does not exist', $metadata: {} })
            );

            await expect(adapter.initiateForgotPassword(username))
                .rejects
                .toThrow(NotFoundError);
        });

        it('should throw BaseError with RateLimitError when too many requests', async () => {
            cognitoMock.on(ForgotPasswordCommand).rejects(
                new LimitExceededException({ message: 'Attempt limit exceeded', $metadata: {} })
            );

            await expect(adapter.initiateForgotPassword(username))
                .rejects
                .toThrow(BaseError);
        });
    });

    describe('confirmForgotPassword', () => {
        const username = 'user@example.com';
        const code = '123456';
        const newPassword = 'NewPassword123!';

        it('should complete successfully with valid code and password', async () => {
            cognitoMock.on(ConfirmForgotPasswordCommand).resolves({});

            await adapter.confirmForgotPassword(username, code, newPassword);

            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Password successfully reset'));
        });

        it('should throw AuthenticationError when code is invalid', async () => {
            cognitoMock.on(ConfirmForgotPasswordCommand).rejects(
                new CodeMismatchException({ message: 'Invalid verification code', $metadata: {} })
            );

            await expect(adapter.confirmForgotPassword(username, code, newPassword))
                .rejects
                .toThrow(AuthenticationError);
        });

        it('should throw ValidationError when new password does not meet requirements', async () => {
            cognitoMock.on(ConfirmForgotPasswordCommand).rejects(
                new InvalidPasswordException({ message: 'Password does not meet requirements', $metadata: {} })
            );

            await expect(adapter.confirmForgotPassword(username, code, newPassword))
                .rejects
                .toThrow(ValidationError);
        });
    });

    describe('adminOperations', () => {
        const username = 'user@example.com';
        const newPassword = 'NewPassword123!';

        describe('adminInitiateForgotPassword', () => {
            it('should complete successfully', async () => {
                cognitoMock.on(AdminResetUserPasswordCommand).resolves({});

                await adapter.adminInitiateForgotPassword(username);

                expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Admin password reset initiated successfully'));
            });

            it('should throw NotFoundError when user does not exist', async () => {
                cognitoMock.on(AdminResetUserPasswordCommand).rejects(
                    new UserNotFoundException({ message: 'User does not exist', $metadata: {} })
                );

                await expect(adapter.adminInitiateForgotPassword(username))
                    .rejects
                    .toThrow(NotFoundError);
            });
        });

        describe('adminSetPassword', () => {
            it('should complete successfully', async () => {
                cognitoMock.on(AdminSetUserPasswordCommand).resolves({});

                await adapter.adminSetPassword(username, newPassword);

                expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Admin password set successfully'));
            });

            it('should throw ValidationError when password does not meet requirements', async () => {
                cognitoMock.on(AdminSetUserPasswordCommand).rejects(
                    new InvalidPasswordException({ message: 'Password does not meet requirements', $metadata: {} })
                );

                await expect(adapter.adminSetPassword(username, newPassword))
                    .rejects
                    .toThrow(ValidationError);
            });

            it('should throw NotFoundError when user does not exist', async () => {
                cognitoMock.on(AdminSetUserPasswordCommand).rejects(
                    new UserNotFoundException({ message: 'User does not exist', $metadata: {} })
                );

                await expect(adapter.adminSetPassword(username, newPassword))
                    .rejects
                    .toThrow(NotFoundError);
            });
        });
    });

    // Additional comprehensive test coverage
    describe('getUserFromToken', () => {
        const accessToken = 'valid-access-token';

        it('should return user attributes successfully', async () => {
            const mockUserResponse = {
                Username: 'testuser',
                UserAttributes: [
                    { Name: 'sub', Value: 'user-sub-123' },
                    { Name: 'email', Value: 'test@example.com' },
                    { Name: 'name', Value: 'Test User' }
                ]
            };

            cognitoMock.on(GetUserCommand).resolves(mockUserResponse);

            const result = await adapter.getUserFromToken(accessToken);

            expect(result).toEqual({
                username: 'testuser',
                sub: 'user-sub-123',
                email: 'test@example.com',
                name: 'Test User'
            });
        });

        it('should handle user with minimal attributes', async () => {
            const mockUserResponse = {
                Username: 'testuser',
                UserAttributes: [
                    { Name: 'sub', Value: 'user-sub-123' }
                ]
            };

            cognitoMock.on(GetUserCommand).resolves(mockUserResponse);

            const result = await adapter.getUserFromToken(accessToken);

            expect(result).toEqual({
                username: 'testuser',
                sub: 'user-sub-123'
            });
        });

        it('should handle user with no attributes', async () => {
            const mockUserResponse = {
                Username: 'testuser',
                UserAttributes: []
            };

            cognitoMock.on(GetUserCommand).resolves(mockUserResponse);

            const result = await adapter.getUserFromToken(accessToken);

            expect(result).toEqual({
                username: 'testuser'
            });
        });

        it('should throw InvalidTokenError when token is invalid', async () => {
            cognitoMock.on(GetUserCommand).rejects(
                new NotAuthorizedException({ message: 'Invalid access token', $metadata: {} })
            );

            await expect(adapter.getUserFromToken(accessToken))
                .rejects
                .toThrow(InvalidTokenError);
        });
    });

    describe('changePassword', () => {
        const accessToken = 'valid-access-token';
        const oldPassword = 'OldPassword123!';
        const newPassword = 'NewPassword123!';

        it('should change password successfully', async () => {
            cognitoMock.on(ChangePasswordCommand).resolves({});

            await adapter.changePassword(accessToken, oldPassword, newPassword);

            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Password changed successfully'));
        });

        it('should throw AuthenticationError when old password is incorrect', async () => {
            cognitoMock.on(ChangePasswordCommand).rejects(
                new NotAuthorizedException({ message: 'Incorrect username or password', $metadata: {} })
            );

            await expect(adapter.changePassword(accessToken, 'wrongpassword', newPassword))
                .rejects
                .toThrow(AuthenticationError);
        });

        it('should throw InvalidTokenError when access token is invalid', async () => {
            cognitoMock.on(ChangePasswordCommand).rejects(
                new NotAuthorizedException({ message: 'Invalid access token', $metadata: {} })
            );

            await expect(adapter.changePassword('invalid-token', oldPassword, newPassword))
                .rejects
                .toThrow(InvalidTokenError);
        });

        it('should throw ValidationError when new password does not meet requirements', async () => {
            cognitoMock.on(ChangePasswordCommand).rejects(
                new InvalidPasswordException({ message: 'Password does not meet requirements', $metadata: {} })
            );

            await expect(adapter.changePassword(accessToken, oldPassword, 'weak'))
                .rejects
                .toThrow(ValidationError);
        });
    });

    describe('respondToAuthChallenge', () => {
        const username = 'testuser';
        const session = 'test-session';
        const challengeResponses = { SMS_MFA_CODE: '123456' };

        it('should successfully respond to MFA challenge', async () => {
            const mockAuthResult = {
                AuthenticationResult: {
                    AccessToken: 'access-token',
                    RefreshToken: 'refresh-token',
                    IdToken: 'id-token',
                    ExpiresIn: 3600,
                    TokenType: 'Bearer'
                }
            };

            cognitoMock.on(RespondToAuthChallengeCommand).resolves(mockAuthResult);

            const result = await adapter.respondToAuthChallenge(
                username,
                session,
                ChallengeNameType.SMS_MFA,
                challengeResponses
            );

            expect(result).toEqual({
                accessToken: 'access-token',
                refreshToken: 'refresh-token',
                idToken: 'id-token',
                expiresIn: 3600,
                tokenType: 'Bearer'
            });
        });

        it('should handle subsequent challenge', async () => {
            const mockChallengeResponse = {
                ChallengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA,
                Session: 'new-session',
                ChallengeParameters: {}
            };

            cognitoMock.on(RespondToAuthChallengeCommand).resolves(mockChallengeResponse);

            await expect(adapter.respondToAuthChallenge(
                username,
                session,
                ChallengeNameType.SMS_MFA,
                challengeResponses
            )).rejects.toThrow(MfaRequiredError);
        });

        it('should throw AuthenticationError when challenge response is invalid', async () => {
            cognitoMock.on(RespondToAuthChallengeCommand).rejects(
                new CodeMismatchException({ message: 'Invalid verification code', $metadata: {} })
            );

            await expect(adapter.respondToAuthChallenge(
                username,
                session,
                ChallengeNameType.SMS_MFA,
                { SMS_MFA_CODE: 'wrong-code' }
            )).rejects.toThrow(AuthenticationError);
        });
    });

    describe('Edge Cases and Error Scenarios', () => {
        it('should handle missing AuthenticationResult in successful auth', async () => {
            cognitoMock.on(InitiateAuthCommand).resolves({});

            await expect(adapter.authenticateUser('testuser', 'password'))
                .rejects
                .toThrow(BaseError);
        });

        it('should handle missing AuthenticationResult in token refresh', async () => {
            cognitoMock.on(InitiateAuthCommand).resolves({});

            await expect(adapter.refreshToken('refresh-token'))
                .rejects
                .toThrow(BaseError);
        });

        it('should handle signup with confirmed user', async () => {
            const mockResponse = {
                UserSub: 'user-sub-123',
                UserConfirmed: true
            };

            cognitoMock.on(SignUpCommand).resolves(mockResponse);

            const result = await adapter.signUp({
                username: 'testuser',
                password: 'Password123!',
                attributes: { email: 'test@example.com' }
            });

            expect(result.userConfirmed).toBe(true);
        });

        it('should handle forgot password without code delivery details', async () => {
            cognitoMock.on(ForgotPasswordCommand).resolves({});

            const result = await adapter.initiateForgotPassword('testuser');

            expect(result).toBeUndefined();
        });

        it('should handle refresh token without RefreshToken in response', async () => {
            const mockAuthResult = {
                AuthenticationResult: {
                    AccessToken: 'new-access-token',
                    ExpiresIn: 3600,
                    TokenType: 'Bearer'
                    // No RefreshToken
                }
            };

            cognitoMock.on(InitiateAuthCommand).resolves(mockAuthResult);

            const result = await adapter.refreshToken('refresh-token');

            expect(result).toEqual({
                accessToken: 'new-access-token',
                expiresIn: 3600,
                tokenType: 'Bearer'
            });
            expect(result.refreshToken).toBeUndefined();
        });
    });

    describe('Logging Coverage', () => {
        it('should log authentication attempts', async () => {
            const mockAuthResult = {
                AuthenticationResult: {
                    AccessToken: 'access-token',
                    RefreshToken: 'refresh-token',
                    IdToken: 'id-token',
                    ExpiresIn: 3600,
                    TokenType: 'Bearer'
                }
            };

            cognitoMock.on(InitiateAuthCommand).resolves(mockAuthResult);

            await adapter.authenticateUser('testuser', 'password');

            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Attempting authentication'));
            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Authentication successful'));
        });

        it('should log signup attempts', async () => {
            const mockResponse = {
                UserSub: 'user-sub-123',
                UserConfirmed: false
            };

            cognitoMock.on(SignUpCommand).resolves(mockResponse);

            await adapter.signUp({
                username: 'testuser',
                password: 'Password123!',
                attributes: { email: 'test@example.com' }
            });

            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Attempting signup'));
            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('Signup successful'));
        });

        it('should log error scenarios', async () => {
            cognitoMock.on(InitiateAuthCommand).rejects(
                new NotAuthorizedException({ message: 'Invalid credentials', $metadata: {} })
            );

            await expect(adapter.authenticateUser('testuser', 'wrongpassword'))
                .rejects
                .toThrow();

            expect(mockLogger.error).toHaveBeenCalled();
        });
    });

    describe('Additional Error Types Coverage', () => {
        it('should handle AliasExistsException', async () => {
            const error = new Error('Email already exists');
            error.name = 'AliasExistsException';

            cognitoMock.on(SignUpCommand).rejects(error);

            await expect(adapter.signUp({
                username: 'testuser',
                password: 'Password123!',
                attributes: { email: 'existing@example.com' }
            })).rejects.toThrow(ValidationError);
        });

        it('should handle CodeDeliveryFailureException', async () => {
            const error = new Error('Failed to deliver code');
            error.name = 'CodeDeliveryFailureException';

            cognitoMock.on(ForgotPasswordCommand).rejects(error);

            await expect(adapter.initiateForgotPassword('testuser'))
                .rejects
                .toThrow(BaseError);
        });

        it('should handle ForbiddenException', async () => {
            const error = new Error('Operation forbidden');
            error.name = 'ForbiddenException';

            cognitoMock.on(GlobalSignOutCommand).rejects(error);

            await expect(adapter.signOut('invalid-token'))
                .rejects
                .toThrow(InvalidTokenError);
        });

        it('should handle ResourceNotFoundException', async () => {
            const error = new Error('Resource not found');
            error.name = 'ResourceNotFoundException';

            cognitoMock.on(InitiateAuthCommand).rejects(error);

            await expect(adapter.authenticateUser('testuser', 'password'))
                .rejects
                .toThrow(NotFoundError);
        });

        it('should handle InternalErrorException', async () => {
            const error = new Error('Internal server error');
            error.name = 'InternalErrorException';

            cognitoMock.on(InitiateAuthCommand).rejects(error);

            await expect(adapter.authenticateUser('testuser', 'password'))
                .rejects
                .toThrow(BaseError);
        });

        it('should handle TooManyFailedAttemptsException', async () => {
            const error = new Error('Too many failed attempts');
            error.name = 'TooManyFailedAttemptsException';

            cognitoMock.on(InitiateAuthCommand).rejects(error);

            await expect(adapter.authenticateUser('testuser', 'password'))
                .rejects
                .toThrow(BaseError);
        });
    });
});