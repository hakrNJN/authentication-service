import {
    AuthenticationResultType,
    ChallengeNameType, // Keep this for challenge tests



    // Import Specific Exception Classes used with createCognitoError
    InitiateAuthCommand,
    InitiateAuthCommandOutput,
    NotAuthorizedException,
    UserNotConfirmedException
} from '@aws-sdk/client-cognito-identity-provider';
import 'reflect-metadata'; // Ensure this runs early
import { IConfigService } from '../../../../../src/application/interfaces/IConfigService';
import { ILogger } from '../../../../../src/application/interfaces/ILogger';
import { container } from '../../../../../src/container';
import {
    InvalidCredentialsError,
    PasswordResetRequiredError,
    UserNotConfirmedError
} from '../../../../../src/domain';
import { CognitoAuthAdapter } from '../../../../../src/infrastructure/adapters/cognito/CognitoAuthAdapter';
import { TYPES } from '../../../../../src/shared/constants/types';
import { mockConfigService, resetMockConfigService } from '../../../../mocks/mockConfigService';
import { mockLogger, resetMockLogger } from '../../../../mocks/mockLogger';


// --- Mock AWS SDK Client ---
// --- Mock AWS SDK Client ---
// Define the single, shared mock function for the send method
const mockSend = jest.fn();

// Mock the entire module
jest.mock('@aws-sdk/client-cognito-identity-provider', () => {
    console.log('--- JEST MOCK FACTORY EXECUTING ---');
    const actual = jest.requireActual('@aws-sdk/client-cognito-identity-provider');
    return {
        ...actual, // Keep actual enums, commands, exceptions
        // Mock the CLIENT CONSTRUCTOR directly in the factory
        CognitoIdentityProviderClient: jest.fn().mockImplementation(() => {
            console.log('--- MOCKED CognitoIdentityProviderClient CONSTRUCTOR CALLED ---');
            // Return the object with the SHARED mockSend function
            return {
                send: mockSend,
                destroy: jest.fn(),
            };
        }),
    };
});

// Get a reference to the mocked constructor for clearing if needed, but don't reconfigure implementation here
const { CognitoIdentityProviderClient: MockCognitoClientConstructor } = jest.requireMock('@aws-sdk/client-cognito-identity-provider');


// --- Helper to Create AWS Errors ---
function createCognitoError(ErrorClass: any, message: string, statusCode = 400) {
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
    const userPoolId = 'us-east-1_testpool';
    const clientId = 'mockclientid123';
    const username = 'testuser@example.com';
    const password = 'Password123!';
    const session = 'long_enough_session_string_for_testing_purpose_value_AYABe...';
    const mockAuthResult: AuthenticationResultType = {
        AccessToken: 'at', RefreshToken: 'rt', IdToken: 'it', ExpiresIn: 3600, TokenType: 'Bearer'
    };

    beforeEach(() => {
        // Reset mocks
        resetMockLogger();
        resetMockConfigService();
        localMockLogger = mockLogger as jest.Mocked<ILogger>;
        localMockConfigService = mockConfigService as jest.Mocked<IConfigService>;

        // Reset the shared mockSend function
        mockSend.mockReset();
        // Reset the constructor mock itself
        MockCognitoClientConstructor.mockClear();

        // Configure config values
        localMockConfigService.get.mockImplementation((key: string) => {
            if (key === 'AWS_REGION') return 'us-east-1';
            if (key === 'COGNITO_USER_POOL_ID') return userPoolId;
            if (key === 'COGNITO_CLIENT_ID') return clientId;
            return undefined;
        });

        // DI setup
        container.clearInstances();
        container.registerInstance<ILogger>(TYPES.Logger, localMockLogger);
        container.registerInstance<IConfigService>(TYPES.ConfigService, localMockConfigService);

        // Resolve adapter - this should trigger the mocked constructor
        adapter = container.resolve(CognitoAuthAdapter);
    });

    // --- Focused Test Cases for authenticateUser ---
    describe.only('authenticateUser', () => {

        // Test 1: Success Case
        it('should return tokens on successful authentication', async () => {
            const output: InitiateAuthCommandOutput = { $metadata: {}, AuthenticationResult: mockAuthResult };
            // Configure the SHARED mockSend for this test
            mockSend.mockResolvedValueOnce(output);

            console.log('--- TEST: Success - Calling adapter.authenticateUser ---');
            const result = await adapter.authenticateUser(username, password);
            console.log('--- TEST: Success - adapter.authenticateUser call completed ---');

            expect(result).toEqual(expect.objectContaining({ accessToken: 'at', refreshToken: 'rt' }));
            // Assert on the SHARED mockSend
            expect(mockSend).toHaveBeenCalledTimes(1);
            expect(mockSend).toHaveBeenCalledWith(expect.any(InitiateAuthCommand));
            console.log('--- TEST: Success - assertions passed ---');
        });

        // Test 2: Challenge Case
        it('should throw PasswordResetRequiredError for NEW_PASSWORD_REQUIRED challenge', async () => {
            const output: InitiateAuthCommandOutput = { $metadata: {}, ChallengeName: ChallengeNameType.NEW_PASSWORD_REQUIRED, Session: session };
            // Configure the SHARED mockSend for this test
            mockSend.mockResolvedValueOnce(output);

            console.log('--- TEST: Challenge - Calling adapter.authenticateUser ---');
            await expect(adapter.authenticateUser(username, password)).rejects.toThrow(PasswordResetRequiredError);
            console.log('--- TEST: Challenge - adapter.authenticateUser rejection confirmed ---');

            // Assert on the SHARED mockSend
            expect(mockSend).toHaveBeenCalledTimes(1);
            console.log('--- TEST: Challenge - assertions passed ---');
        });

        // Test 3: Specific Known Error Case
        it('should throw InvalidCredentialsError for NotAuthorizedException (wrong password)', async () => {
            const error = createCognitoError(NotAuthorizedException, 'Incorrect username or password.');
            // Configure the SHARED mockSend for this test
            mockSend.mockRejectedValueOnce(error);

            console.log('--- TEST: NotAuthorized - Calling adapter.authenticateUser ---');
            await expect(adapter.authenticateUser(username, 'wrongpass')).rejects.toThrow(InvalidCredentialsError);
            console.log('--- TEST: NotAuthorized - adapter.authenticateUser rejection confirmed ---');

            // Assert on the SHARED mockSend
            expect(mockSend).toHaveBeenCalledTimes(1);
            console.log('--- TEST: NotAuthorized - assertions passed ---');
        });

        // Test 4: Different Known Error Case
        it('should throw UserNotConfirmedError for UserNotConfirmedException', async () => {
            const error = createCognitoError(UserNotConfirmedException, 'User is not confirmed.');
            // Configure the SHARED mockSend for this test
            mockSend.mockRejectedValueOnce(error);

            console.log('--- TEST: UserNotConfirmed - Calling adapter.authenticateUser ---');
             // Use the specific domain error alias if needed, otherwise the direct class name
            await expect(adapter.authenticateUser(username, password)).rejects.toThrow(UserNotConfirmedError );
            console.log('--- TEST: UserNotConfirmed - adapter.authenticateUser rejection confirmed ---');

            // Assert on the SHARED mockSend
            expect(mockSend).toHaveBeenCalledTimes(1);
            console.log('--- TEST: UserNotConfirmed - assertions passed ---');
        });
    });
});