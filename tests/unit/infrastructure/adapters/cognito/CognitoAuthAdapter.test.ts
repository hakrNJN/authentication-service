import {
    AuthenticationResultType,
    ChallengeNameType,
    InitiateAuthCommandOutput,
    RespondToAuthChallengeCommandOutput,
    // Add other specific error classes used in tests
    UserNotFoundException
} from '@aws-sdk/client-cognito-identity-provider';
import { container } from '../../../../../src/container';
import { CognitoAuthAdapter } from '../../../../../src/infrastructure/adapters/cognito/CognitoAuthAdapter';
import { TYPES } from '../../../../../src/shared/constants/types';
import { NotFoundError } from '../../../../../src/shared/errors/BaseError';
import { mockConfigService } from '../../../../mocks/mockConfigService';
import { mockLogger } from '../../../../mocks/mockLogger';

// --- AWS Error Creation Helper ---
// Keep this helper, it's good for simulating specific errors
function createAwsError(ErrorClass: any, message: string, name?: string) {
    // AWS SDK v3 errors often have $metadata. Error constructor might vary slightly.
    const error = new ErrorClass({ message, $metadata: {} });
    // Crucially, ensure the 'name' property matches what Cognito throws
    Object.defineProperty(error, 'name', {
        value: name || ErrorClass.name, // Use provided name or class name
        configurable: true,
        writable: true,
    });
    return error;
}


// --- Mock AWS SDK Client ---
// Define the mock send function *outside* the mock factory
const mockSend = jest.fn();

jest.mock('@aws-sdk/client-cognito-identity-provider', () => {
    console.log('--- [MOCK] Applying Cognito SDK Mock ---');
    const actualSdk = jest.requireActual('@aws-sdk/client-cognito-identity-provider');

    const MockCognitoClient = jest.fn().mockImplementation((config) => {
        console.log(`--- [MOCK] Mock CognitoIdentityProviderClient CONSTRUCTOR CALLED ---`);
        const instance = {
            send: mockSend,
            destroy: jest.fn(),
            // Add other methods/props if needed by adapter logic
        };
        console.log(`--- [MOCK] Mock Client Instance CREATED with send type: ${typeof instance.send} ---`);
        return instance;
    });

    return {
        __esModule: true, // Helps with ES module interop
        ...actualSdk, // Spread actuals first
        CognitoIdentityProviderClient: MockCognitoClient, // Override constructor
        // Ensure REAL error classes are exported for instanceof checks
        NotAuthorizedException: actualSdk.NotAuthorizedException,
        UserNotFoundException: actualSdk.UserNotFoundException,
        // ... include ALL specific error classes used in handleCognitoError
        UsernameExistsException: actualSdk.UsernameExistsException,
        UserNotConfirmedException: actualSdk.UserNotConfirmedException,
        PasswordResetRequiredException: actualSdk.PasswordResetRequiredException,
        InvalidPasswordException: actualSdk.InvalidPasswordException,
        InvalidParameterException: actualSdk.InvalidParameterException,
        CodeMismatchException: actualSdk.CodeMismatchException,
        ExpiredCodeException: actualSdk.ExpiredCodeException,
        CodeDeliveryFailureException: actualSdk.CodeDeliveryFailureException,
        LimitExceededException: actualSdk.LimitExceededException,
        TooManyRequestsException: actualSdk.TooManyRequestsException,
        TooManyFailedAttemptsException: actualSdk.TooManyFailedAttemptsException,
        ForbiddenException: actualSdk.ForbiddenException,
        ResourceNotFoundException: actualSdk.ResourceNotFoundException,
        InternalErrorException: actualSdk.InternalErrorException,
    };
});

describe('CognitoAuthAdapter', () => {
    let adapter: CognitoAuthAdapter;
    const username = 'testuser';
    const password = 'Password123!';
    const accessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test';
    // Use a simplified session string for tests unless the exact format is critical
    const session = 'mockSessionString123';
    const code = '123456';

    beforeEach(() => {
        // Clear tsyringe instances
        container.clearInstances();
        // Reset the mock send function before each test
        mockSend.mockReset();
        // Reset mocks for commands if they track calls/instances
        // jest.mocked(InitiateAuthCommand).mockClear(); // Example if using jest.mocked

        // Ensure mocks for dependencies are reset if they track calls
        jest.mocked(mockConfigService.get).mockClear();
        jest.mocked(mockLogger.info).mockClear();
        jest.mocked(mockLogger.warn).mockClear();
        jest.mocked(mockLogger.error).mockClear();
        jest.mocked(mockLogger.debug).mockClear();

        // Mock required config values
        jest.mocked(mockConfigService.get).mockImplementation((key: string) => {
            switch (key) {
                case 'AWS_REGION':
                    return 'us-east-1';
                case 'COGNITO_USER_POOL_ID':
                    return 'us-east-1_testpool';
                case 'COGNITO_CLIENT_ID':
                    return 'testclientid123'; // Use a clearer mock value
                default:
                    return undefined;
            }
        });

        // Register mock instances in the container
        container.registerInstance(TYPES.Logger, mockLogger);
        container.registerInstance(TYPES.ConfigService, mockConfigService);

        console.log('--- [TEST] Before resolving adapter ---');

        // Resolve the adapter - this will now use the mocked Cognito Client
        try {
            adapter = container.resolve(CognitoAuthAdapter);
        } catch (e) {
            console.error("--- [TEST] Error during container.resolve:", e);
            throw e; // Re-throw to fail test clearly if constructor check fails
        }
        console.log('--- [TEST] After resolving adapter ---');
    });

    // --- Test Suites ---

    describe('authenticateUser', () => {
        const mockAuthResult: AuthenticationResultType = {
            AccessToken: 'at',
            IdToken: 'idt', // Include IdToken if mapped
            RefreshToken: 'rt',
            ExpiresIn: 3600,
            TokenType: 'Bearer'
        };

        it('should return tokens on successful USER_PASSWORD_AUTH', async () => {
            const output: InitiateAuthCommandOutput = {
                $metadata: {},
                AuthenticationResult: mockAuthResult
            };
            mockSend.mockResolvedValueOnce(output);

            // Add logging right before the call
            console.log(`--- [TEST] Calling authenticateUser. Adapter client send type: ${typeof (adapter as any)?.client?.send}`);

            const result = await adapter.authenticateUser(username, password);

            expect(result).toEqual({
                accessToken: 'at',
                idToken: 'idt',
                refreshToken: 'rt',
                expiresIn: 3600,
                tokenType: 'Bearer'
            });
            // Verify the correct command input was sent
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                AuthFlow: 'USER_PASSWORD_AUTH',    
                ClientId: 'testclientid123',
                AuthParameters: { USERNAME: username, PASSWORD: password },
            }));
        });

        // it('should throw MfaRequiredError for SOFTWARE_TOKEN_MFA challenge', async () => {
        //     const challengeParams = { USERNAME: 'testuser', DEVICE_KEY: 'somekey' };
        //     const output: InitiateAuthCommandOutput = {
        //         $metadata: {},
        //         Session: session, // Use the defined mock session
        //         ChallengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA,
        //         ChallengeParameters: challengeParams
        //     };
        //     mockSend.mockResolvedValueOnce(output);

        //     // Using .rejects.toThrow with class checks the error type
        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(MfaRequiredError);

        //     // Using .rejects.toMatchObject checks specific properties
        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toMatchObject({
        //             session: session,
        //             challengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA,
        //             challengeParameters: challengeParams,
        //             name: 'MfaRequiredError' // Check custom error name if defined
        //         });
        // });

        // it('should throw PasswordResetRequiredError for NEW_PASSWORD_REQUIRED challenge', async () => {
        //      const output: InitiateAuthCommandOutput = {
        //         $metadata: {},
        //         Session: session, // Session might be present
        //         ChallengeName: ChallengeNameType.NEW_PASSWORD_REQUIRED,
        //         ChallengeParameters: {}
        //     };
        //     mockSend.mockResolvedValueOnce(output);

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(PasswordResetRequiredError);
        // });

        // it('should throw InvalidCredentialsError for NotAuthorizedException', async () => {
        //     // Use the helper to create the specific AWS error
        //     const awsError = createAwsError(NotAuthorizedException, 'Incorrect username or password.');
        //     mockSend.mockRejectedValueOnce(awsError);

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(InvalidCredentialsError);
        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toMatchObject({ message: 'Incorrect username or password.'});
        // });

        // it('should throw UserNotConfirmedError for UserNotConfirmedException', async () => {
        //     const awsError = createAwsError(UserNotConfirmedException, 'User is not confirmed.');
        //     mockSend.mockRejectedValueOnce(awsError);

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(UserNotConfirmedError);
        // });

        // it('should throw AuthenticationError for unhandled challenge', async () => {
        //     const output: InitiateAuthCommandOutput = {
        //         $metadata: {},
        //         Session: session,
        //         // Use a challenge name not explicitly handled in the switch case
        //         ChallengeName: ChallengeNameType.CUSTOM_CHALLENGE,
        //         ChallengeParameters: {}
        //     };
        //     mockSend.mockResolvedValueOnce(output);

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(AuthenticationError);
        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(`Unhandled authentication challenge: ${ChallengeNameType.CUSTOM_CHALLENGE}`);
        // });

        //  it('should throw AuthenticationError if MFA challenge lacks session', async () => {
        //     const output: InitiateAuthCommandOutput = {
        //         $metadata: {},
        //         Session: undefined, // No session
        //         ChallengeName: ChallengeNameType.SMS_MFA,
        //         ChallengeParameters: {}
        //     };
        //     mockSend.mockResolvedValueOnce(output);

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(AuthenticationError);
        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow('MFA challenge is incomplete.');
        // });

        // it('should throw AuthenticationError for unexpected response (no result/challenge)', async () => {
        //     const output: InitiateAuthCommandOutput = { // Empty response
        //         $metadata: {},
        //     };
        //     mockSend.mockResolvedValueOnce(output);

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(AuthenticationError);
        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow('Unexpected authentication response.');
        // });
    });

    describe('respondToAuthChallenge', () => {
        const mockAuthResult: AuthenticationResultType = {
            AccessToken: 'at-from-challenge',
            IdToken: 'idt-from-challenge',
            RefreshToken: 'rt-from-challenge',
            ExpiresIn: 3600,
            TokenType: 'Bearer'
        };
        const challengeResponses = { SMS_MFA_CODE: code };
        const challengeName = ChallengeNameType.SMS_MFA;

        it('should return tokens on successful challenge response', async () => {
            const output: RespondToAuthChallengeCommandOutput = {
                $metadata: {},
                AuthenticationResult: mockAuthResult
            };
            mockSend.mockResolvedValueOnce(output);

            const result = await adapter.respondToAuthChallenge(
                username, // Note: Cognito RespondToAuthChallenge doesn't always need username in params
                session,
                challengeName,
                challengeResponses
            );

            expect(result).toEqual({
                accessToken: 'at-from-challenge',
                idToken: 'idt-from-challenge',
                refreshToken: 'rt-from-challenge',
                expiresIn: 3600,
                tokenType: 'Bearer'
            });
            expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
                ClientId: 'testclientid123',
                ChallengeName: challengeName,
                Session: session,
                ChallengeResponses: challengeResponses,
            }));
        });

    //     it('should throw MfaRequiredError if another challenge is presented', async () => {
    //         const nextChallengeName = ChallengeNameType.SOFTWARE_TOKEN_MFA;
    //         const nextSession = 'nextSession123';
    //         const output: RespondToAuthChallengeCommandOutput = {
    //             $metadata: {},
    //             ChallengeName: nextChallengeName,
    //             Session: nextSession,
    //             ChallengeParameters: { USERNAME: 'testuser' }
    //         };
    //         mockSend.mockResolvedValueOnce(output);

    //         await expect(adapter.respondToAuthChallenge(username, session, challengeName, challengeResponses))
    //             .rejects.toThrow(MfaRequiredError);
    //         await expect(adapter.respondToAuthChallenge(username, session, challengeName, challengeResponses))
    //             .rejects.toMatchObject({
    //                 session: nextSession,
    //                 challengeName: nextChallengeName,
    //                 challengeParameters: { USERNAME: 'testuser' }
    //             });
    //     });

    //     it('should throw AuthenticationError for CodeMismatchException', async () => {
    //         const awsError = createAwsError(CodeMismatchException, 'Invalid verification code provided.');
    //         mockSend.mockRejectedValueOnce(awsError);

    //         await expect(adapter.respondToAuthChallenge(username, session, challengeName, challengeResponses))
    //             .rejects.toThrow(AuthenticationError);
    //         await expect(adapter.respondToAuthChallenge(username, session, challengeName, challengeResponses))
    //              .rejects.toMatchObject({ message: 'Invalid verification code', statusCode: 400 }); // Check mapped message/status
    //     });

    //     it('should throw AuthenticationError for ExpiredCodeException', async () => {
    //         const awsError = createAwsError(ExpiredCodeException, 'Code has expired.');
    //         mockSend.mockRejectedValueOnce(awsError);

    //         await expect(adapter.respondToAuthChallenge(username, session, challengeName, challengeResponses))
    //             .rejects.toThrow(AuthenticationError);
    //         await expect(adapter.respondToAuthChallenge(username, session, challengeName, challengeResponses))
    //              .rejects.toMatchObject({ message: 'Verification code has expired', statusCode: 400 });
    //     });

    //      it('should throw AuthenticationError if subsequent challenge lacks session', async () => {
    //         const output: RespondToAuthChallengeCommandOutput = {
    //             $metadata: {},
    //             ChallengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA,
    //             Session: undefined, // No session
    //             ChallengeParameters: {}
    //         };
    //         mockSend.mockResolvedValueOnce(output);

    //         await expect(adapter.respondToAuthChallenge(username, session, challengeName, challengeResponses))
    //             .rejects.toThrow(AuthenticationError);
    //          await expect(adapter.respondToAuthChallenge(username, session, challengeName, challengeResponses))
    //             .rejects.toThrow('Subsequent challenge is incomplete.');
    //     });

    //     it('should throw AuthenticationError for unexpected response (no result/challenge)', async () => {
    //         const output: RespondToAuthChallengeCommandOutput = { // Empty response
    //             $metadata: {},
    //         };
    //         mockSend.mockResolvedValueOnce(output);

    //         await expect(adapter.respondToAuthChallenge(username, session, challengeName, challengeResponses))
    //             .rejects.toThrow(AuthenticationError);
    //         await expect(adapter.respondToAuthChallenge(username, session, challengeName, challengeResponses))
    //             .rejects.toThrow('Unexpected response after challenge.');
    //     });
    // });

    // describe('signOut', () => {
    //     it('should resolve successfully on global sign out', async () => {
    //         const output: GlobalSignOutCommandOutput = { $metadata: {} };
    //         mockSend.mockResolvedValueOnce(output);

    //         await expect(adapter.signOut(accessToken)).resolves.toBeUndefined();
    //         expect(mockSend).toHaveBeenCalledWith(expect.objectContaining({
    //             AccessToken: accessToken,
    //         }));
    //         expect(mockLogger.info).toHaveBeenCalledWith('Global sign out successful.');
    //     });

    //     it('should throw InvalidTokenError for ForbiddenException', async () => {
    //         // ForbiddenException often means the token is invalid/expired for signout
    //         const awsError = createAwsError(ForbiddenException, 'Access token is invalid');
    //         mockSend.mockRejectedValueOnce(awsError);

    //         await expect(adapter.signOut(accessToken))
    //             .rejects.toThrow(InvalidTokenError);
    //         await expect(adapter.signOut(accessToken))
    //              .rejects.toMatchObject({ message: 'Access token is invalid' }); // Check mapped message
    //     });

    //      it('should throw InvalidTokenError for NotAuthorizedException containing Access Token message', async () => {
    //         // Sometimes NotAuthorized is used for bad tokens too
    //         const awsError = createAwsError(NotAuthorizedException, 'Invalid Access Token');
    //         mockSend.mockRejectedValueOnce(awsError);

    //         await expect(adapter.signOut(accessToken))
    //             .rejects.toThrow(InvalidTokenError);
    //          await expect(adapter.signOut(accessToken))
    //              .rejects.toMatchObject({ message: 'Invalid Access Token' });
    //     });
    });

    describe('handleCognitoError (implicitly tested via other methods)', () => {
        // Test specific error mappings not covered above

        it('should throw NotFoundError for UserNotFoundException', async () => {
             // Use a method that can throw UserNotFound, e.g., initiateForgotPassword
            const awsError = createAwsError(UserNotFoundException, 'User not found.');
            mockSend.mockRejectedValueOnce(awsError);

            await expect(adapter.initiateForgotPassword(username))
                .rejects.toThrow(NotFoundError);
             await expect(adapter.initiateForgotPassword(username))
                .rejects.toMatchObject({ message: 'User not found' });
        });

        // it('should throw ValidationError for UsernameExistsException', async () => {
        //      // Use signUp
        //     const awsError = createAwsError(UsernameExistsException, 'Username already exists.');
        //     mockSend.mockRejectedValueOnce(awsError);

        //     await expect(adapter.signUp({ username, password, attributes: { email: 'test@test.com'} }))
        //         .rejects.toThrow(ValidationError);
        //     await expect(adapter.signUp({ username, password, attributes: { email: 'test@test.com'} }))
        //         .rejects.toMatchObject({ message: 'Username already exists' });
        // });

        // it('should throw ValidationError for InvalidPasswordException', async () => {
        //      // Use signUp or changePassword
        //     const awsError = createAwsError(InvalidPasswordException, 'Password does not meet requirements.');
        //     mockSend.mockRejectedValueOnce(awsError);

        //     await expect(adapter.signUp({ username, password, attributes: { email: 'test@test.com'} }))
        //         .rejects.toThrow(ValidationError);
        //     await expect(adapter.signUp({ username, password, attributes: { email: 'test@test.com'} }))
        //          .rejects.toMatchObject({ message: 'Password does not meet requirements.' });
        // });

        // it('should throw ValidationError for InvalidParameterException', async () => {
        //     const awsError = createAwsError(InvalidParameterException, 'Invalid email address format.');
        //     mockSend.mockRejectedValueOnce(awsError);

        //      await expect(adapter.signUp({ username, password, attributes: { email: 'invalid-email'} }))
        //         .rejects.toThrow(ValidationError);
        //     await expect(adapter.signUp({ username, password, attributes: { email: 'invalid-email'} }))
        //          .rejects.toMatchObject({ message: 'Invalid email address format.' });
        // });

        // it('should throw BaseError with status 429 for LimitExceededException', async () => {
        //     const awsError = createAwsError(LimitExceededException, 'Too many requests');
        //     mockSend.mockRejectedValueOnce(awsError);

        //     // Use any method, e.g., authenticateUser
        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(BaseError); // Check base type
        //      await expect(adapter.authenticateUser(username, password))
        //         .rejects.toMatchObject({ name: 'RateLimitError', statusCode: 429, message: 'Too many requests' });
        // });

        // it('should throw BaseError with status 429 for TooManyRequestsException', async () => {
        //     const awsError = createAwsError(TooManyRequestsException, 'Calm down');
        //      mockSend.mockRejectedValueOnce(awsError);

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(BaseError);
        //      await expect(adapter.authenticateUser(username, password))
        //         .rejects.toMatchObject({ name: 'RateLimitError', statusCode: 429, message: 'Calm down' });
        // });

        // it('should throw NotFoundError for ResourceNotFoundException', async () => {
        //     // E.g., if user pool doesn't exist (less common in unit tests)
        //     const awsError = createAwsError(ResourceNotFoundException, 'User pool not found.');
        //      mockSend.mockRejectedValueOnce(awsError);

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(NotFoundError);
        //     await expect(adapter.authenticateUser(username, password))
        //          .rejects.toMatchObject({ message: 'User pool not found.' });
        // });

        //  it('should throw BaseError with status 502 for InternalErrorException', async () => {
        //     const awsError = createAwsError(InternalErrorException, 'Cognito hiccup');
        //      mockSend.mockRejectedValueOnce(awsError);

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(BaseError);
        //     await expect(adapter.authenticateUser(username, password))
        //          .rejects.toMatchObject({ name: 'IdPInternalError', statusCode: 502, message: 'Identity provider internal error' });
        // });

        // it('should throw BaseError (IdPError) for unmapped Cognito errors', async () => {
        //     // Create a generic error with a name not in the switch case
        //     const error = new Error('Something weird happened');
        //     error.name = 'SomeUnknownCognitoError';
        //     mockSend.mockRejectedValueOnce(error);

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(BaseError); // Check base type
        //     await expect(adapter.authenticateUser(username, password))
        //          .rejects.toMatchObject({
        //              name: 'IdPError',
        //              statusCode: 500,
        //              message: 'An unexpected identity provider error occurred: Something weird happened', // Check the constructed message
        //          });
        // });

        //  it('should throw BaseError (IdPError) for generic non-AWS errors', async () => {
        //     // Simulate a network error or something else
        //     const error = new Error('Network failed');
        //     mockSend.mockRejectedValueOnce(error); // No specific 'name' property

        //     await expect(adapter.authenticateUser(username, password))
        //         .rejects.toThrow(BaseError);
        //     await expect(adapter.authenticateUser(username, password))
        //          .rejects.toMatchObject({
        //              name: 'IdPError',
        //              statusCode: 500,
        //              message: 'An unexpected identity provider error occurred: Network failed',
        //          });
        // });
    });

    // Add tests for other methods (refreshToken, getUserFromToken, signUp, confirmSignUp, etc.)
    // following the same pattern: mock send, call adapter method, assert success/error.
});