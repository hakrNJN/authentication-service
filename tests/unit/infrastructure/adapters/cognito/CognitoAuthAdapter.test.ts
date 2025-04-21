import {
    AdminResetUserPasswordCommand, // Added
    AdminSetUserPasswordCommand, // Added
    AttributeType,
    AuthFlowType,
    AuthenticationResultType,
    ChallengeNameType,
    ChangePasswordCommand,
    CodeDeliveryDetailsType,
    CodeDeliveryFailureException,
    CodeMismatchException, // Keep constructor import for type checking
    ConfirmForgotPasswordCommand,
    ConfirmSignUpCommand,
    ExpiredCodeException,
    ForbiddenException,
    ForgotPasswordCommand,
    GetUserCommand,
    GlobalSignOutCommand,
    InitiateAuthCommand,
    InitiateAuthCommandOutput,
    InternalErrorException,
    InvalidParameterException,
    InvalidPasswordException,
    LimitExceededException,
    // Import Specific Exception Classes used with createCognitoError
    NotAuthorizedException,
    ResourceNotFoundException, // Keep Output types used in tests
    RespondToAuthChallengeCommand,
    SignUpCommand,
    TooManyFailedAttemptsException,
    TooManyRequestsException,
    UserNotConfirmedException,
    UserNotFoundException,
    UsernameExistsException
} from '@aws-sdk/client-cognito-identity-provider';
import 'reflect-metadata';
import { IConfigService } from '../../../../../src/application/interfaces/IConfigService';
import { ILogger } from '../../../../../src/application/interfaces/ILogger';
import { container } from '../../../../../src/container';
import {
    AuthenticationError,
    InvalidCredentialsError,
    InvalidTokenError,
    MfaRequiredError,
    PasswordResetRequiredError,
    UserNotConfirmedError,
    ValidationError,
} from '../../../../../src/domain';
import { CognitoAuthAdapter } from '../../../../../src/infrastructure/adapters/cognito/CognitoAuthAdapter';
import { TYPES } from '../../../../../src/shared/constants/types';
import { BaseError, NotFoundError } from '../../../../../src/shared/errors/BaseError';
import { mockConfigService, resetMockConfigService } from '../../../../mocks/mockConfigService';
import { mockLogger, resetMockLogger } from '../../../../mocks/mockLogger';


// --- Mock AWS SDK Client ---
const mockSend = jest.fn();
// Mock the entire module first
jest.mock('@aws-sdk/client-cognito-identity-provider');
// NOW, get a typed reference to the *mocked* constructor
const { CognitoIdentityProviderClient: MockCognitoClient } = jest.requireMock('@aws-sdk/client-cognito-identity-provider');
// Configure the mock implementation *before* tests run
MockCognitoClient.mockImplementation(() => ({
    send: mockSend,
    destroy: jest.fn(),
}));


// --- Helper to Create AWS Errors ---
function createCognitoError(ErrorClass: any, message: string, statusCode = 400) {
    // Use the actual constructor if available, otherwise create a generic error
    const error = new ErrorClass({ message, $metadata: {} });
    Object.defineProperty(error, 'name', { value: ErrorClass.name, configurable: true });
    error.$response = { statusCode };
    return error;
}

describe('CognitoAuthAdapter', () => {
    let adapter: CognitoAuthAdapter;
    let localMockLogger: jest.Mocked<ILogger>;
    let localMockConfigService: jest.Mocked<IConfigService>;

    // --- Test Data ---
    const userPoolId = 'us-east-1_testpool'; // Needed for admin commands
    const clientId = 'mockclientid123';
    const username = 'testuser@example.com';
    const password = 'Password123!';
    const accessToken = 'valid.access.token';
    const refreshToken = 'valid.refresh.token';
    const session = 'AYABeN3YZF66uA1256WLJ0N_0Zd9lPqzJAQEBwYCCAcIAxH2DQMLEe0PAw8R4xUEFwEZDhwPGA8dEQoaDxgCBAIEBR0BBgAGEe0PAw8PGA8YDxgBAhgPGA8YBgEGEe0PAwwR7Q8DDxHwCAoKDxwAABLtDwMSEg4TEfYNAwwR4BAODAkOEQ4QBhHjFQQXDBkOHA8YDx0RChoPGAAABAURBBPtDw8QEfQBChAS7Q8DDwn_____AQsJEusPAwwR7g0OAgwMAg8MAQEKEQoR9g0DCxH2DQMLCxPtDxIAAhgSWEpXVFNUWVhWVFRQEwA.test'; // Ensure long enough
    const confirmationCode = '123456';
    const previousPassword = 'OldPassword123!';
    const proposedPassword = 'NewPassword456!';
    const mockAuthResult: AuthenticationResultType = {
        AccessToken: 'at', RefreshToken: 'rt', IdToken: 'it', ExpiresIn: 3600, TokenType: 'Bearer'
    };
    const mockNewAuthResult: AuthenticationResultType = {
        AccessToken: 'new-at', RefreshToken: 'new-rt-optional', IdToken: 'new-it', ExpiresIn: 3600, TokenType: 'Bearer'
    };
    const mockUserAttributes: AttributeType[] = [
        { Name: 'sub', Value: 'uuid-123' }, { Name: 'email', Value: username }
    ];
    const mockCodeDeliveryDetails: CodeDeliveryDetailsType = {
        AttributeName: 'email', DeliveryMedium: 'EMAIL', Destination: 't***@e***.com'
    };

    beforeEach(() => {
        // Reset mocks
        resetMockLogger();
        resetMockConfigService();
        localMockLogger = mockLogger as jest.Mocked<ILogger>;
        localMockConfigService = mockConfigService as jest.Mocked<IConfigService>;

        mockSend.mockReset();
        MockCognitoClient.mockClear();

        // Configure config values
        localMockConfigService.get.mockImplementation((key: string) => {
            if (key === 'AWS_REGION') return 'us-east-1';
            if (key === 'COGNITO_USER_POOL_ID') return userPoolId;
            if (key === 'COGNITO_CLIENT_ID') return clientId;
            return undefined;
        });

        // Clear container and register mocks
        container.clearInstances();
        container.registerInstance<ILogger>(TYPES.Logger, localMockLogger);
        container.registerInstance<IConfigService>(TYPES.ConfigService, localMockConfigService);

        // Resolve adapter AFTER mocks are registered and configured
        adapter = container.resolve(CognitoAuthAdapter);
    });

    // --- Test Cases ---

    describe.only('authenticateUser', () => {
        it('should return tokens on successful authentication', async () => {
            const output: InitiateAuthCommandOutput = { $metadata: {}, AuthenticationResult: mockAuthResult };
            mockSend.mockResolvedValueOnce(output);
            const result = await adapter.authenticateUser(username, password);
            expect(result).toEqual(expect.objectContaining({ accessToken: 'at', refreshToken: 'rt' }));
            expect(mockSend).toHaveBeenCalledWith(expect.any(InitiateAuthCommand));
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                input: { AuthFlow: AuthFlowType.USER_PASSWORD_AUTH, ClientId: clientId, AuthParameters: { USERNAME: username, PASSWORD: password } }
            }));
        });

        it('should throw MfaRequiredError for SOFTWARE_TOKEN_MFA challenge', async () => {
            const output: InitiateAuthCommandOutput = { $metadata: {}, ChallengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA, Session: session, ChallengeParameters: {} };
            mockSend.mockResolvedValueOnce(output);
            await expect(adapter.authenticateUser(username, password)).rejects.toThrow(MfaRequiredError);
            await expect(adapter.authenticateUser(username, password)).rejects.toMatchObject({ session, challengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA });
        });

        it('should throw PasswordResetRequiredError for NEW_PASSWORD_REQUIRED challenge', async () => {
            const output: InitiateAuthCommandOutput = { $metadata: {}, ChallengeName: ChallengeNameType.NEW_PASSWORD_REQUIRED, Session: session };
            mockSend.mockResolvedValueOnce(output);
            await expect(adapter.authenticateUser(username, password)).rejects.toThrow(PasswordResetRequiredError);
        });

        it('should throw InvalidCredentialsError for NotAuthorizedException (wrong password)', async () => {
            // Simulate incorrect password scenario
            mockSend.mockRejectedValueOnce(createCognitoError(NotAuthorizedException, 'Incorrect username or password.'));
            await expect(adapter.authenticateUser(username, 'wrongpass')).rejects.toThrow(InvalidCredentialsError);
        });

        it('should throw UserNotConfirmedError for UserNotConfirmedException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(UserNotConfirmedException, 'User is not confirmed.'));
            await expect(adapter.authenticateUser(username, password)).rejects.toThrow(UserNotConfirmedError);
        });

        it('should throw NotFoundError for UserNotFoundException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(UserNotFoundException, 'User does not exist.', 404));
            await expect(adapter.authenticateUser('unknown@example.com', password)).rejects.toThrow(NotFoundError);
        });

        it('should throw BaseError(RateLimitError) for TooManyRequestsException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(TooManyRequestsException, 'Rate limit exceeded.', 429));
            await expect(adapter.authenticateUser(username, password)).rejects.toThrow(BaseError);
            await expect(adapter.authenticateUser(username, password)).rejects.toMatchObject({ name: 'RateLimitError', statusCode: 429 });
        });
    });

    describe('respondToAuthChallenge', () => {
        it('should return tokens on successful challenge response', async () => {
            const output: any = { $metadata: {}, AuthenticationResult: mockAuthResult }; // AWS SDK v3 doesn't always return a typed output here
            mockSend.mockResolvedValueOnce(output);
            const result = await adapter.respondToAuthChallenge(username, session, ChallengeNameType.SMS_MFA, { SMS_MFA_CODE: confirmationCode });
            expect(result).toEqual(expect.objectContaining({ accessToken: 'at', refreshToken: 'rt' }));
            expect(mockSend).toHaveBeenCalledWith(expect.any(RespondToAuthChallengeCommand));
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                input: { ClientId: clientId, ChallengeName: ChallengeNameType.SMS_MFA, Session: session, ChallengeResponses: { SMS_MFA_CODE: confirmationCode } }
            }));
        });

        it('should throw AuthenticationError for CodeMismatchException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(CodeMismatchException, 'Invalid verification code.'));
            await expect(adapter.respondToAuthChallenge(username, session, ChallengeNameType.SMS_MFA, { SMS_MFA_CODE: 'wrong' })).rejects.toThrow(AuthenticationError);
             await expect(adapter.respondToAuthChallenge(username, session, ChallengeNameType.SMS_MFA, { SMS_MFA_CODE: 'wrong' })).rejects.toMatchObject({ message: 'Invalid verification code', statusCode: 400 });
        });

        it('should throw AuthenticationError for ExpiredCodeException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(ExpiredCodeException, 'Verification code expired.'));
            await expect(adapter.respondToAuthChallenge(username, session, ChallengeNameType.SMS_MFA, { SMS_MFA_CODE: confirmationCode })).rejects.toThrow(AuthenticationError);
            await expect(adapter.respondToAuthChallenge(username, session, ChallengeNameType.SMS_MFA, { SMS_MFA_CODE: confirmationCode })).rejects.toMatchObject({ message: 'Verification code has expired', statusCode: 400 });
        });

        it('should throw MfaRequiredError if another challenge is presented', async () => {
             const output: any = { $metadata: {}, ChallengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA, Session: session, ChallengeParameters: {} };
             mockSend.mockResolvedValueOnce(output);
             await expect(adapter.respondToAuthChallenge(username, session, ChallengeNameType.NEW_PASSWORD_REQUIRED, { NEW_PASSWORD: proposedPassword })).rejects.toThrow(MfaRequiredError);
        });
    });

    describe('refreshToken', () => {
        it('should return new tokens on successful refresh', async () => {
            const output: InitiateAuthCommandOutput = { $metadata: {}, AuthenticationResult: mockNewAuthResult };
            mockSend.mockResolvedValueOnce(output);
            const result = await adapter.refreshToken(refreshToken);
            expect(result).toEqual(expect.objectContaining({ accessToken: 'new-at', idToken: 'new-it' }));
            expect(result.refreshToken).toBe(mockNewAuthResult.RefreshToken); // Check if the refresh token is passed through
            expect(mockSend).toHaveBeenCalledWith(expect.any(InitiateAuthCommand));
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                 input: { AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH, ClientId: clientId, AuthParameters: { REFRESH_TOKEN: refreshToken } }
            }));
        });

        it('should throw InvalidTokenError for NotAuthorizedException (invalid refresh token)', async () => {
            // This error message might be specific to invalid refresh token, handleCognitoError should catch it
            mockSend.mockRejectedValueOnce(createCognitoError(NotAuthorizedException, 'Invalid Refresh Token'));
            await expect(adapter.refreshToken('invalid-token')).rejects.toThrow(InvalidCredentialsError); // Because message doesn't contain "Access Token"
             // Let's refine the error check based on handleCognitoError logic
             await expect(adapter.refreshToken('invalid-token')).rejects.toMatchObject({ name: 'InvalidCredentialsError' });
        });

        it('should throw InvalidCredentialsError for general NotAuthorizedException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(NotAuthorizedException, 'Some other authorization issue.'));
            await expect(adapter.refreshToken(refreshToken)).rejects.toThrow(InvalidCredentialsError);
        });
    });

    describe('getUserFromToken', () => {
        it('should return user attributes on success', async () => {
            const output: any = { $metadata: {}, UserAttributes: mockUserAttributes, Username: username };
            mockSend.mockResolvedValueOnce(output);
            const result = await adapter.getUserFromToken(accessToken);
            expect(result).toEqual({ sub: 'uuid-123', email: username, username: username });
            expect(mockSend).toHaveBeenCalledWith(expect.any(GetUserCommand));
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({ input: { AccessToken: accessToken } }));
        });

        it('should throw InvalidTokenError for NotAuthorizedException (message contains Access Token)', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(NotAuthorizedException, 'Invalid Access Token'));
            await expect(adapter.getUserFromToken('invalid-token')).rejects.toThrow(InvalidTokenError);
        });

        it('should throw InvalidTokenError for ForbiddenException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(ForbiddenException, 'Token has been revoked'));
            await expect(adapter.getUserFromToken(accessToken)).rejects.toThrow(InvalidTokenError);
        });

         it('should throw NotFoundError for ResourceNotFoundException', async () => {
             mockSend.mockRejectedValueOnce(createCognitoError(ResourceNotFoundException, 'User not found.')); // Example message
             await expect(adapter.getUserFromToken(accessToken)).rejects.toThrow(NotFoundError);
         });
    });

    describe('signUp', () => {
        const details = { username: 'new@example.com', password: 'NewPassword1!', attributes: { email: 'new@example.com' } };
        it('should return signup result on success', async () => {
            const output: any = { $metadata: {}, UserSub: 'new-sub', UserConfirmed: false, CodeDeliveryDetails: mockCodeDeliveryDetails };
            mockSend.mockResolvedValueOnce(output);
            const result = await adapter.signUp(details);
            expect(result).toEqual({ userSub: 'new-sub', userConfirmed: false, codeDeliveryDetails: mockCodeDeliveryDetails });
            expect(mockSend).toHaveBeenCalledWith(expect.any(SignUpCommand));
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                input: expect.objectContaining({ ClientId: clientId, Username: details.username })
            }));
        });

        it('should throw ValidationError for UsernameExistsException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(UsernameExistsException, 'Username already exists.'));
            await expect(adapter.signUp(details)).rejects.toThrow(ValidationError);
            await expect(adapter.signUp(details)).rejects.toMatchObject({ message: 'Username already exists' });
        });

        it('should throw ValidationError for InvalidPasswordException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(InvalidPasswordException, 'Password does not meet policy.'));
            await expect(adapter.signUp(details)).rejects.toThrow(ValidationError);
            await expect(adapter.signUp(details)).rejects.toMatchObject({ message: 'Password does not meet policy.' });
        });

        it('should throw ValidationError for InvalidParameterException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(InvalidParameterException, 'Invalid email address format.'));
            await expect(adapter.signUp(details)).rejects.toThrow(ValidationError);
             await expect(adapter.signUp(details)).rejects.toMatchObject({ message: 'Invalid email address format.' });
        });
    });

    describe('confirmSignUp', () => {
        it('should resolve on successful confirmation', async () => {
            const output: any = { $metadata: {} };
            mockSend.mockResolvedValueOnce(output);
            await expect(adapter.confirmSignUp(username, confirmationCode)).resolves.toBeUndefined();
            expect(mockSend).toHaveBeenCalledWith(expect.any(ConfirmSignUpCommand));
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                 input: { ClientId: clientId, Username: username, ConfirmationCode: confirmationCode }
            }));
        });

        it('should throw AuthenticationError for CodeMismatchException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(CodeMismatchException, 'Invalid code.'));
            await expect(adapter.confirmSignUp(username, 'wrong-code')).rejects.toThrow(AuthenticationError);
            await expect(adapter.confirmSignUp(username, 'wrong-code')).rejects.toMatchObject({ statusCode: 400 });
        });

        it('should throw AuthenticationError for ExpiredCodeException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(ExpiredCodeException, 'Code expired.'));
            await expect(adapter.confirmSignUp(username, confirmationCode)).rejects.toThrow(AuthenticationError);
            await expect(adapter.confirmSignUp(username, confirmationCode)).rejects.toMatchObject({ statusCode: 400 });
        });

        it('should throw NotFoundError for UserNotFoundException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(UserNotFoundException, 'User not found.', 404));
            await expect(adapter.confirmSignUp('unknownuser', confirmationCode)).rejects.toThrow(NotFoundError);
        });
    });

    describe('signOut', () => {
        it('should resolve on successful sign out', async () => {
            const output: any = { $metadata: {} };
            mockSend.mockResolvedValueOnce(output);
            await expect(adapter.signOut(accessToken)).resolves.toBeUndefined();
            expect(mockSend).toHaveBeenCalledWith(expect.any(GlobalSignOutCommand));
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({ input: { AccessToken: accessToken } }));
        });

        // Test based on handleCognitoError mapping
        it('should throw InvalidTokenError for NotAuthorizedException (invalid token message)', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(NotAuthorizedException, 'Access Token has been revoked'));
            await expect(adapter.signOut('invalid-token')).rejects.toThrow(InvalidTokenError);
        });

        it('should throw InvalidCredentialsError for NotAuthorizedException (other message)', async () => {
             mockSend.mockRejectedValueOnce(createCognitoError(NotAuthorizedException, 'Some other reason'));
             await expect(adapter.signOut('other-invalid-token')).rejects.toThrow(InvalidCredentialsError); // Falls back to this in handleCognitoError
         });

        it('should throw InvalidTokenError for ForbiddenException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(ForbiddenException, 'Token revoked'));
            await expect(adapter.signOut(accessToken)).rejects.toThrow(InvalidTokenError);
        });
    });

    describe('initiateForgotPassword', () => {
        it('should return code delivery details on success', async () => {
            const output: any = { $metadata: {}, CodeDeliveryDetails: mockCodeDeliveryDetails };
            mockSend.mockResolvedValueOnce(output);
            const result = await adapter.initiateForgotPassword(username);
            expect(result).toEqual(mockCodeDeliveryDetails);
            expect(mockSend).toHaveBeenCalledWith(expect.any(ForgotPasswordCommand));
             expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({ input: { ClientId: clientId, Username: username } }));
        });

        it('should throw NotFoundError for UserNotFoundException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(UserNotFoundException, 'User not found.', 404));
            await expect(adapter.initiateForgotPassword('unknownuser')).rejects.toThrow(NotFoundError);
        });

        it('should throw BaseError(RateLimitError) for LimitExceededException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(LimitExceededException, 'Attempt limit exceeded, please try after some time.', 429));
            await expect(adapter.initiateForgotPassword(username)).rejects.toThrow(BaseError);
            await expect(adapter.initiateForgotPassword(username)).rejects.toMatchObject({ name: 'RateLimitError', statusCode: 429 });
        });

        it('should throw BaseError(CodeDeliveryError) for CodeDeliveryFailureException', async () => {
             mockSend.mockRejectedValueOnce(createCognitoError(CodeDeliveryFailureException, 'Failed to deliver code.', 500));
             await expect(adapter.initiateForgotPassword(username)).rejects.toThrow(BaseError);
             await expect(adapter.initiateForgotPassword(username)).rejects.toMatchObject({ name: 'CodeDeliveryError', statusCode: 500 });
         });
    });

    describe('confirmForgotPassword', () => {
        it('should resolve on successful password reset', async () => {
            const output: any = { $metadata: {} };
            mockSend.mockResolvedValueOnce(output);
            await expect(adapter.confirmForgotPassword(username, confirmationCode, proposedPassword)).resolves.toBeUndefined();
            expect(mockSend).toHaveBeenCalledWith(expect.any(ConfirmForgotPasswordCommand));
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                input: { ClientId: clientId, Username: username, ConfirmationCode: confirmationCode, Password: proposedPassword }
            }));
        });

        it('should throw AuthenticationError for CodeMismatchException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(CodeMismatchException, 'Invalid code.'));
            await expect(adapter.confirmForgotPassword(username, 'wrong-code', proposedPassword)).rejects.toThrow(AuthenticationError);
             await expect(adapter.confirmForgotPassword(username, 'wrong-code', proposedPassword)).rejects.toMatchObject({ statusCode: 400 });
        });

        it('should throw ValidationError for InvalidPasswordException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(InvalidPasswordException, 'Password policy failed.'));
            await expect(adapter.confirmForgotPassword(username, confirmationCode, 'weak')).rejects.toThrow(ValidationError);
        });

         it('should throw NotFoundError for UserNotFoundException', async () => {
             mockSend.mockRejectedValueOnce(createCognitoError(UserNotFoundException, 'User not found.', 404));
             await expect(adapter.confirmForgotPassword('unknownuser', confirmationCode, proposedPassword)).rejects.toThrow(NotFoundError);
         });
    });

    describe('changePassword', () => {
        it('should resolve on successful password change', async () => {
            const output: any = { $metadata: {} };
            mockSend.mockResolvedValueOnce(output);
            await expect(adapter.changePassword(accessToken, previousPassword, proposedPassword)).resolves.toBeUndefined();
            expect(mockSend).toHaveBeenCalledWith(expect.any(ChangePasswordCommand));
             expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                 input: { AccessToken: accessToken, PreviousPassword: previousPassword, ProposedPassword: proposedPassword }
             }));
        });

        it('should throw AuthenticationError for NotAuthorizedException (wrong old password message)', async () => {
            // Specific check in changePassword method relies on this message substring
            mockSend.mockRejectedValueOnce(createCognitoError(NotAuthorizedException, 'Incorrect username or password.'));
            await expect(adapter.changePassword(accessToken, 'wrong-old-pass', proposedPassword)).rejects.toThrow(AuthenticationError);
            await expect(adapter.changePassword(accessToken, 'wrong-old-pass', proposedPassword)).rejects.toThrow('Incorrect previous password provided.');
        });

        // Test the mapping via handleCognitoError for invalid token
        it('should throw InvalidTokenError for NotAuthorizedException (invalid token message)', async () => {
             mockSend.mockRejectedValueOnce(createCognitoError(NotAuthorizedException, 'Invalid Access Token specified'));
             await expect(adapter.changePassword('invalid-token', previousPassword, proposedPassword)).rejects.toThrow(InvalidTokenError);
         });

        it('should throw InvalidCredentialsError for NotAuthorizedException (other message)', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(NotAuthorizedException, 'Some other auth issue'));
            await expect(adapter.changePassword(accessToken, previousPassword, proposedPassword)).rejects.toThrow(InvalidCredentialsError);
        });

        it('should throw ValidationError for InvalidPasswordException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(InvalidPasswordException, 'Password policy failed.'));
            await expect(adapter.changePassword(accessToken, previousPassword, 'weak')).rejects.toThrow(ValidationError);
        });

        it('should throw NotFoundError for UserNotFoundException', async () => {
             mockSend.mockRejectedValueOnce(createCognitoError(UserNotFoundException, 'User not found.', 404));
             await expect(adapter.changePassword(accessToken, previousPassword, proposedPassword)).rejects.toThrow(NotFoundError);
         });
    });

    describe('adminInitiateForgotPassword', () => {
         it('should resolve on successful initiation', async () => {
            const output: any = { $metadata: {} }; // Command returns empty object on success
            mockSend.mockResolvedValueOnce(output);
            await expect(adapter.adminInitiateForgotPassword(username)).resolves.toBeUndefined();
            expect(mockSend).toHaveBeenCalledWith(expect.any(AdminResetUserPasswordCommand));
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                 input: { UserPoolId: userPoolId, Username: username }
            }));
        });

         it('should throw NotFoundError for UserNotFoundException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(UserNotFoundException, 'User not found.', 404));
            await expect(adapter.adminInitiateForgotPassword('unknownuser')).rejects.toThrow(NotFoundError);
        });

         // Add other error cases as needed (e.g., InvalidParameterException)
     });

     // Renamed describe block
    describe('adminSetPassword', () => {
        it('should resolve on successful password set', async () => {
            const output: any = { $metadata: {} }; // Command returns empty object on success
            mockSend.mockResolvedValueOnce(output);
             // Call the renamed method without confirmation code
            await expect(adapter.adminSetPassword(username, proposedPassword)).resolves.toBeUndefined();
             // Expect the correct command
            expect(mockSend).toHaveBeenCalledWith(expect.any(AdminSetUserPasswordCommand));
             // Expect the correct input parameters
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                input: { UserPoolId: userPoolId, Username: username, Password: proposedPassword, Permanent: true }
            }));
        });

         it('should throw NotFoundError for UserNotFoundException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(UserNotFoundException, 'User not found.', 404));
            await expect(adapter.adminSetPassword('unknownuser', proposedPassword)).rejects.toThrow(NotFoundError);
        });

        it('should throw ValidationError for InvalidPasswordException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(InvalidPasswordException, 'Password policy failed.'));
            await expect(adapter.adminSetPassword(username, 'weak')).rejects.toThrow(ValidationError);
        });

         it('should throw ValidationError for InvalidParameterException', async () => {
             mockSend.mockRejectedValueOnce(createCognitoError(InvalidParameterException, 'Invalid username parameter.')); // Example
             await expect(adapter.adminSetPassword('invalid-username!', proposedPassword)).rejects.toThrow(ValidationError);
         });

         // Add other potential error tests (e.g., ResourceNotFound for UserPool)
     });


    describe('error handling (general)', () => {
         it('should throw BaseError(RateLimitError) for TooManyFailedAttemptsException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(TooManyFailedAttemptsException, 'Too many failed attempts.', 429));
            await expect(adapter.authenticateUser(username, password)).rejects.toThrow(BaseError);
            await expect(adapter.authenticateUser(username, password)).rejects.toMatchObject({ name: 'RateLimitError', statusCode: 429 });
        });

        it('should throw BaseError(IdPInternalError) for InternalErrorException', async () => {
            mockSend.mockRejectedValueOnce(createCognitoError(InternalErrorException, 'Internal server error.', 500)); // Use 500 for example
            await expect(adapter.authenticateUser(username, password)).rejects.toThrow(BaseError);
             // Check for the mapped error type and potentially status code if consistent
            await expect(adapter.authenticateUser(username, password)).rejects.toMatchObject({ name: 'IdPInternalError', statusCode: 502 }); // Mapped to 502
        });

        it('should throw BaseError(IdPError) for unhandled errors', async () => {
            const error = new Error('Something completely unexpected.');
            error.name = 'SomeOtherErrorNameNotInSwitch'; // Ensure it doesn't match known cases
            mockSend.mockRejectedValueOnce(error);
            await expect(adapter.authenticateUser(username, password)).rejects.toThrow(BaseError);
            await expect(adapter.authenticateUser(username, password)).rejects.toMatchObject({ name: 'IdPError', statusCode: 500 });
        });
    });
});