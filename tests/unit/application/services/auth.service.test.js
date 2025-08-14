"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
jest.mock('../../../../src/infrastructure/resilience/applyResilience', () => ({
    applyCircuitBreaker: (fn) => fn,
}));
const client_cognito_identity_provider_1 = require("@aws-sdk/client-cognito-identity-provider");
require("reflect-metadata"); // Required for tsyringe
const auth_service_1 = require("../../../../src/application/services/auth.service");
const container_1 = require("../../../../src/container");
const domain_1 = require("../../../../src/domain");
const types_1 = require("../../../../src/shared/constants/types");
const BaseError_1 = require("../../../../src/shared/errors/BaseError");
const mockAuthAdapter_1 = require("../../../mocks/mockAuthAdapter");
const mockConfigService_1 = require("../../../mocks/mockConfigService");
const mockLogger_1 = require("../../../mocks/mockLogger");
describe('AuthService', () => {
    let authService;
    beforeEach(() => {
        jest.clearAllMocks();
        // Clear container instances and register mocks
        container_1.container.clearInstances();
        container_1.container.registerInstance(types_1.TYPES.AuthAdapter, mockAuthAdapter_1.mockAuthAdapter);
        container_1.container.registerInstance(types_1.TYPES.Logger, mockLogger_1.mockLogger);
        container_1.container.registerInstance(types_1.TYPES.ConfigService, mockConfigService_1.mockConfigService);
        authService = container_1.container.resolve(auth_service_1.AuthService);
    });
    // --- Login ---
    describe('login', () => {
        it('should return tokens on successful login', async () => {
            const tokens = { accessToken: 'a', refreshToken: 'r', expiresIn: 3600, tokenType: 'Bearer' };
            mockAuthAdapter_1.mockAuthAdapter.authenticateUser.mockResolvedValue(tokens);
            const result = await authService.login('user', 'pass');
            expect(result).toEqual(tokens);
            expect(mockAuthAdapter_1.mockAuthAdapter.authenticateUser).toHaveBeenCalledWith('user', 'pass');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Login attempt for user: user');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Login successful for user: user');
        });
        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.login('', 'pass')).rejects.toThrow(domain_1.ValidationError);
            expect(mockAuthAdapter_1.mockAuthAdapter.authenticateUser).not.toHaveBeenCalled();
        });
        it('should throw ValidationError if password is missing', async () => {
            await expect(authService.login('user', '')).rejects.toThrow(domain_1.ValidationError);
            expect(mockAuthAdapter_1.mockAuthAdapter.authenticateUser).not.toHaveBeenCalled();
        });
        it('should re-throw MfaRequiredError from adapter', async () => {
            const mfaError = new domain_1.MfaRequiredError('sess', client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA, {});
            mockAuthAdapter_1.mockAuthAdapter.authenticateUser.mockRejectedValue(mfaError);
            await expect(authService.login('user', 'pass')).rejects.toThrow(domain_1.MfaRequiredError);
            expect(mockLogger_1.mockLogger.warn).toHaveBeenCalledWith(expect.stringContaining('MFA required for user user'));
        });
        it('should re-throw other operational errors from adapter', async () => {
            const authError = new domain_1.AuthenticationError('Invalid credentials');
            mockAuthAdapter_1.mockAuthAdapter.authenticateUser.mockRejectedValue(authError);
            await expect(authService.login('user', 'pass')).rejects.toThrow(domain_1.AuthenticationError);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Login failed for user user'), expect.any(domain_1.AuthenticationError));
        });
        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('Something broke');
            mockAuthAdapter_1.mockAuthAdapter.authenticateUser.mockRejectedValue(unexpectedError);
            await expect(authService.login('user', 'pass')).rejects.toThrow(domain_1.AuthenticationError); // Wraps as AuthenticationError
            await expect(authService.login('user', 'pass')).rejects.toThrow('Login failed: Something broke');
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Login failed for user user'), unexpectedError);
        });
    });
    // --- Verify MFA ---
    describe('verifyMfa', () => {
        const username = 'user';
        const session = 'sess123';
        const code = '123456';
        const tokens = { accessToken: 'a', refreshToken: 'r', expiresIn: 3600, tokenType: 'Bearer' };
        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.verifyMfa('', session, client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA, code)).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if session is missing', async () => {
            await expect(authService.verifyMfa(username, '', client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA, code)).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if challengeName is missing', async () => {
            await expect(authService.verifyMfa(username, session, '', code)).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if code is missing', async () => {
            await expect(authService.verifyMfa(username, session, client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA, '')).rejects.toThrow(domain_1.ValidationError);
        });
        it('should call adapter with correct SMS_MFA responses and return tokens', async () => {
            mockAuthAdapter_1.mockAuthAdapter.respondToAuthChallenge.mockResolvedValue(tokens);
            const expectedResponses = { SMS_MFA_CODE: code, USERNAME: username };
            const result = await authService.verifyMfa(username, session, client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA, code);
            expect(result).toEqual(tokens);
            expect(mockAuthAdapter_1.mockAuthAdapter.respondToAuthChallenge).toHaveBeenCalledWith(username, session, client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA, expectedResponses);
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith(`Verifying MFA challenge ${client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA} for user: ${username}`);
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith(`MFA verification successful for user: ${username}`);
        });
        it('should call adapter with correct SOFTWARE_TOKEN_MFA responses and return tokens', async () => {
            mockAuthAdapter_1.mockAuthAdapter.respondToAuthChallenge.mockResolvedValue(tokens);
            const expectedResponses = { SOFTWARE_TOKEN_MFA_CODE: code, USERNAME: username };
            const result = await authService.verifyMfa(username, session, client_cognito_identity_provider_1.ChallengeNameType.SOFTWARE_TOKEN_MFA, code);
            expect(result).toEqual(tokens);
            expect(mockAuthAdapter_1.mockAuthAdapter.respondToAuthChallenge).toHaveBeenCalledWith(username, session, client_cognito_identity_provider_1.ChallengeNameType.SOFTWARE_TOKEN_MFA, expectedResponses);
        });
        it('should call adapter with correct DEVICE_PASSWORD_VERIFIER responses and return tokens', async () => {
            mockAuthAdapter_1.mockAuthAdapter.respondToAuthChallenge.mockResolvedValue(tokens);
            const passkeyResponse = { id: 'deviceKey123', response: { signature: 'sig123' } };
            const passkeyCode = JSON.stringify(passkeyResponse);
            // Note: Timestamp will vary, so use expect.any(String) or mock Date
            const expectedResponses = expect.objectContaining({
                USERNAME: username,
                DEVICE_KEY: passkeyResponse.id,
                CHALLENGE_SIGNATURE: passkeyResponse.response.signature,
                TIMESTAMP: expect.any(String),
            });
            const result = await authService.verifyMfa(username, session, client_cognito_identity_provider_1.ChallengeNameType.DEVICE_PASSWORD_VERIFIER, passkeyCode);
            expect(result).toEqual(tokens);
            expect(mockAuthAdapter_1.mockAuthAdapter.respondToAuthChallenge).toHaveBeenCalledWith(username, session, client_cognito_identity_provider_1.ChallengeNameType.DEVICE_PASSWORD_VERIFIER, expectedResponses);
        });
        it('should throw ValidationError if DEVICE_PASSWORD_VERIFIER code is invalid JSON', async () => {
            const invalidJsonCode = '{ "id": "key", '; // Invalid JSON
            await expect(authService.verifyMfa(username, session, client_cognito_identity_provider_1.ChallengeNameType.DEVICE_PASSWORD_VERIFIER, invalidJsonCode)).rejects.toThrow(domain_1.ValidationError);
            expect(mockAuthAdapter_1.mockAuthAdapter.respondToAuthChallenge).not.toHaveBeenCalled();
        });
        it('should throw ValidationError for unsupported challenge type', async () => {
            await expect(authService.verifyMfa(username, session, client_cognito_identity_provider_1.ChallengeNameType.CUSTOM_CHALLENGE, code)).rejects.toThrow(domain_1.ValidationError);
            expect(mockAuthAdapter_1.mockAuthAdapter.respondToAuthChallenge).not.toHaveBeenCalled();
        });
        it('should re-throw operational errors from adapter', async () => {
            const authError = new domain_1.AuthenticationError('Invalid code');
            mockAuthAdapter_1.mockAuthAdapter.respondToAuthChallenge.mockRejectedValue(authError);
            await expect(authService.verifyMfa(username, session, client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA, code)).rejects.toThrow(domain_1.AuthenticationError);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('MFA verification failed'), authError);
        });
        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('Cognito down');
            mockAuthAdapter_1.mockAuthAdapter.respondToAuthChallenge.mockRejectedValue(unexpectedError);
            await expect(authService.verifyMfa(username, session, client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA, code)).rejects.toThrow(domain_1.AuthenticationError);
            await expect(authService.verifyMfa(username, session, client_cognito_identity_provider_1.ChallengeNameType.SMS_MFA, code)).rejects.toThrow('MFA verification failed: Cognito down');
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('MFA verification failed'), unexpectedError);
        });
    });
    // --- Refresh ---
    describe('refresh', () => {
        it('should return tokens on successful refresh', async () => {
            const tokens = { accessToken: 'a', expiresIn: 3600, tokenType: 'Bearer' };
            mockAuthAdapter_1.mockAuthAdapter.refreshToken.mockResolvedValue(tokens);
            const result = await authService.refresh('old_refresh');
            expect(result).toEqual(tokens);
            expect(mockAuthAdapter_1.mockAuthAdapter.refreshToken).toHaveBeenCalledWith('old_refresh');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Token refresh requested.');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Token refresh successful.');
        });
        it('should throw ValidationError if refreshToken is missing', async () => {
            await expect(authService.refresh('')).rejects.toThrow(domain_1.ValidationError);
            expect(mockAuthAdapter_1.mockAuthAdapter.refreshToken).not.toHaveBeenCalled();
        });
        it('should re-throw AuthenticationError from adapter', async () => {
            const authError = new domain_1.AuthenticationError('Invalid token');
            mockAuthAdapter_1.mockAuthAdapter.refreshToken.mockRejectedValue(authError);
            await expect(authService.refresh('invalid_token')).rejects.toThrow(domain_1.AuthenticationError);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Token refresh failed'), authError);
        });
        it('should wrap non-AuthenticationError errors from adapter', async () => {
            const unexpectedError = new Error('Network issue');
            mockAuthAdapter_1.mockAuthAdapter.refreshToken.mockRejectedValue(unexpectedError);
            await expect(authService.refresh('valid_token')).rejects.toThrow(domain_1.AuthenticationError);
            await expect(authService.refresh('valid_token')).rejects.toThrow('Token refresh failed: Network issue');
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Token refresh failed'), unexpectedError);
        });
    });
    // --- Get User Info ---
    describe('getUserInfo', () => {
        it('should return user info on success', async () => {
            const userInfo = { sub: 'uuid', email: 'test@example.com' };
            mockAuthAdapter_1.mockAuthAdapter.getUserFromToken.mockResolvedValue(userInfo);
            const result = await authService.getUserInfo('valid_token');
            expect(result).toEqual(userInfo);
            expect(mockAuthAdapter_1.mockAuthAdapter.getUserFromToken).toHaveBeenCalledWith('valid_token');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Get user info requested.');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Get user info successful.');
        });
        it('should throw ValidationError if accessToken is missing', async () => {
            await expect(authService.getUserInfo('')).rejects.toThrow(domain_1.ValidationError);
            expect(mockAuthAdapter_1.mockAuthAdapter.getUserFromToken).not.toHaveBeenCalled();
        });
        it('should re-throw AuthenticationError from adapter', async () => {
            const authError = new domain_1.AuthenticationError('Invalid token');
            mockAuthAdapter_1.mockAuthAdapter.getUserFromToken.mockRejectedValue(authError);
            await expect(authService.getUserInfo('invalid_token')).rejects.toThrow(domain_1.AuthenticationError);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Get user info failed'), authError);
        });
        it('should wrap non-AuthenticationError errors from adapter', async () => {
            const unexpectedError = new Error('Cognito issue');
            mockAuthAdapter_1.mockAuthAdapter.getUserFromToken.mockRejectedValue(unexpectedError);
            await expect(authService.getUserInfo('valid_token')).rejects.toThrow(domain_1.AuthenticationError);
            await expect(authService.getUserInfo('valid_token')).rejects.toThrow('Failed to retrieve user info: Cognito issue');
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Get user info failed'), unexpectedError);
        });
    });
    // --- Sign Up ---
    describe('signUp', () => {
        const details = { username: 'newuser', password: 'password123', attributes: { email: 'new@example.com' } };
        const result = { userSub: 'uuid', userConfirmed: false };
        it('should return signup result on success', async () => {
            mockAuthAdapter_1.mockAuthAdapter.signUp.mockResolvedValue(result);
            const response = await authService.signUp(details);
            expect(response).toEqual(result);
            expect(mockAuthAdapter_1.mockAuthAdapter.signUp).toHaveBeenCalledWith(details);
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith(`Signup attempt for username: ${details.username}`);
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith(expect.stringContaining(`Signup successful for ${details.username}`));
        });
        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.signUp(Object.assign(Object.assign({}, details), { username: '' }))).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if password is missing', async () => {
            await expect(authService.signUp(Object.assign(Object.assign({}, details), { password: '' }))).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if email attribute is missing', async () => {
            await expect(authService.signUp(Object.assign(Object.assign({}, details), { attributes: {} }))).rejects.toThrow(domain_1.ValidationError);
        });
        it('should re-throw operational errors from adapter', async () => {
            const validationError = new domain_1.ValidationError('Username already exists.');
            mockAuthAdapter_1.mockAuthAdapter.signUp.mockRejectedValue(validationError);
            await expect(authService.signUp(details)).rejects.toThrow(domain_1.ValidationError);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Signup failed'), validationError);
        });
        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('AWS down');
            mockAuthAdapter_1.mockAuthAdapter.signUp.mockRejectedValue(unexpectedError);
            await expect(authService.signUp(details)).rejects.toThrow(BaseError_1.BaseError); // Wraps as BaseError
            await expect(authService.signUp(details)).rejects.toThrow('Signup failed: AWS down');
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Signup failed'), unexpectedError);
        });
    });
    // --- Confirm Sign Up ---
    describe('confirmSignUp', () => {
        it('should complete successfully', async () => {
            mockAuthAdapter_1.mockAuthAdapter.confirmSignUp.mockResolvedValue(undefined);
            await expect(authService.confirmSignUp('user', '123456')).resolves.toBeUndefined();
            expect(mockAuthAdapter_1.mockAuthAdapter.confirmSignUp).toHaveBeenCalledWith('user', '123456');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Attempting signup confirmation for: user');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Signup confirmed for: user');
        });
        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.confirmSignUp('', '123456')).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if confirmationCode is missing', async () => {
            await expect(authService.confirmSignUp('user', '')).rejects.toThrow(domain_1.ValidationError);
        });
        it('should re-throw known errors (Auth, NotFound) from adapter', async () => {
            const authError = new domain_1.AuthenticationError('Code mismatch');
            mockAuthAdapter_1.mockAuthAdapter.confirmSignUp.mockRejectedValue(authError);
            await expect(authService.confirmSignUp('user', 'wrong')).rejects.toThrow(domain_1.AuthenticationError);
            const notFoundError = new BaseError_1.NotFoundError('User');
            mockAuthAdapter_1.mockAuthAdapter.confirmSignUp.mockRejectedValue(notFoundError);
            await expect(authService.confirmSignUp('user', '123')).rejects.toThrow(BaseError_1.NotFoundError);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledTimes(2);
        });
        it('should wrap unexpected errors from adapter', async () => {
            const unexpectedError = new Error('Network glitch');
            mockAuthAdapter_1.mockAuthAdapter.confirmSignUp.mockRejectedValue(unexpectedError);
            await expect(authService.confirmSignUp('user', '123')).rejects.toThrow(domain_1.AuthenticationError); // Wraps as Auth Error
            await expect(authService.confirmSignUp('user', '123')).rejects.toThrow('Confirmation failed: Network glitch');
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Signup confirmation failed'), unexpectedError);
        });
    });
    // --- SignOut ---
    describe('signOut', () => {
        it('should complete successfully', async () => {
            mockAuthAdapter_1.mockAuthAdapter.signOut.mockResolvedValue(undefined);
            await expect(authService.signOut('valid_token')).resolves.toBeUndefined();
            expect(mockAuthAdapter_1.mockAuthAdapter.signOut).toHaveBeenCalledWith('valid_token');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Logout requested.');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Logout successful.');
        });
        it('should throw ValidationError if accessToken is missing', async () => {
            await expect(authService.signOut('')).rejects.toThrow(domain_1.ValidationError);
        });
        it('should re-throw AuthenticationError from adapter', async () => {
            const authError = new domain_1.AuthenticationError('Invalid token');
            mockAuthAdapter_1.mockAuthAdapter.signOut.mockRejectedValue(authError);
            await expect(authService.signOut('invalid')).rejects.toThrow(domain_1.AuthenticationError);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Logout failed'), authError);
        });
        it('should wrap unexpected errors from adapter', async () => {
            const unexpectedError = new Error('Server issue');
            mockAuthAdapter_1.mockAuthAdapter.signOut.mockRejectedValue(unexpectedError);
            await expect(authService.signOut('valid')).rejects.toThrow(domain_1.AuthenticationError); // Wraps as Auth Error
            await expect(authService.signOut('valid')).rejects.toThrow('Logout failed: Server issue');
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Logout failed'), unexpectedError);
        });
    });
    // --- Initiate Forgot Password ---
    describe('initiateForgotPassword', () => {
        const username = 'user';
        const deliveryDetails = { Destination: 'a***@b.com', DeliveryMedium: 'EMAIL', AttributeName: 'email' };
        it('should return delivery details on success', async () => {
            mockAuthAdapter_1.mockAuthAdapter.initiateForgotPassword.mockResolvedValue(deliveryDetails);
            const result = await authService.initiateForgotPassword(username);
            expect(result).toEqual(deliveryDetails);
            expect(mockAuthAdapter_1.mockAuthAdapter.initiateForgotPassword).toHaveBeenCalledWith(username);
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith(`Initiating forgot password process for user: ${username}`);
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith(`Forgot password initiated for ${username}.`);
        });
        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.initiateForgotPassword('')).rejects.toThrow(domain_1.ValidationError);
        });
        it('should re-throw operational errors from adapter', async () => {
            const notFoundError = new BaseError_1.NotFoundError('User'); // Example operational error
            mockAuthAdapter_1.mockAuthAdapter.initiateForgotPassword.mockRejectedValue(notFoundError);
            await expect(authService.initiateForgotPassword(username)).rejects.toThrow(BaseError_1.NotFoundError);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Initiate forgot password failed'), notFoundError);
        });
        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('SES issue');
            mockAuthAdapter_1.mockAuthAdapter.initiateForgotPassword.mockRejectedValue(unexpectedError);
            await expect(authService.initiateForgotPassword(username)).rejects.toThrow(BaseError_1.BaseError); // Wraps as BaseError
            await expect(authService.initiateForgotPassword(username)).rejects.toThrow('Forgot password initiation failed: SES issue');
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Initiate forgot password failed'), unexpectedError);
        });
    });
    // --- Confirm Forgot Password ---
    describe('confirmForgotPassword', () => {
        const username = 'user';
        const code = '123456';
        const newPassword = 'NewPassword123!';
        it('should complete successfully', async () => {
            mockAuthAdapter_1.mockAuthAdapter.confirmForgotPassword.mockResolvedValue(undefined);
            await expect(authService.confirmForgotPassword(username, code, newPassword)).resolves.toBeUndefined();
            expect(mockAuthAdapter_1.mockAuthAdapter.confirmForgotPassword).toHaveBeenCalledWith(username, code, newPassword);
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith(`Confirming forgot password for user: ${username}`);
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith(`Password reset successfully for user: ${username}`);
        });
        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.confirmForgotPassword('', code, newPassword)).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if code is missing', async () => {
            await expect(authService.confirmForgotPassword(username, '', newPassword)).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if newPassword is missing', async () => {
            await expect(authService.confirmForgotPassword(username, code, '')).rejects.toThrow(domain_1.ValidationError);
        });
        it('should re-throw operational errors from adapter', async () => {
            // Use actual Cognito exceptions if adapter maps them, or domain errors
            const codeMismatch = new domain_1.AuthenticationError('Code mismatch'); // Assuming adapter maps CodeMismatchException
            mockAuthAdapter_1.mockAuthAdapter.confirmForgotPassword.mockRejectedValue(codeMismatch);
            await expect(authService.confirmForgotPassword(username, 'wrong', newPassword)).rejects.toThrow(domain_1.AuthenticationError);
            const limitExceeded = new client_cognito_identity_provider_1.LimitExceededException({ $metadata: {}, message: 'Limit exceeded' }); // Raw SDK exception
            mockAuthAdapter_1.mockAuthAdapter.confirmForgotPassword.mockRejectedValue(limitExceeded);
            await expect(authService.confirmForgotPassword(username, code, newPassword)).rejects.toThrow(client_cognito_identity_provider_1.LimitExceededException);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledTimes(2);
        });
        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('DB connection failed');
            mockAuthAdapter_1.mockAuthAdapter.confirmForgotPassword.mockRejectedValue(unexpectedError);
            await expect(authService.confirmForgotPassword(username, code, newPassword)).rejects.toThrow(BaseError_1.BaseError); // Wraps as BaseError
            await expect(authService.confirmForgotPassword(username, code, newPassword)).rejects.toThrow('Password reset confirmation failed: DB connection failed');
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Confirm forgot password failed'), unexpectedError);
        });
    });
    // --- Change Password ---
    describe('changePassword', () => {
        const token = 'valid_token';
        const oldPass = 'OldPassword123';
        const newPass = 'NewPassword456!';
        it('should complete successfully', async () => {
            mockAuthAdapter_1.mockAuthAdapter.changePassword.mockResolvedValue(undefined);
            await expect(authService.changePassword(token, oldPass, newPass)).resolves.toBeUndefined();
            expect(mockAuthAdapter_1.mockAuthAdapter.changePassword).toHaveBeenCalledWith(token, oldPass, newPass);
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Attempting password change for authenticated user.');
            expect(mockLogger_1.mockLogger.info).toHaveBeenCalledWith('Password changed successfully for the user.');
        });
        it('should throw ValidationError if token is missing', async () => {
            await expect(authService.changePassword('', oldPass, newPass)).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if oldPassword is missing', async () => {
            await expect(authService.changePassword(token, '', newPass)).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if newPassword is missing', async () => {
            await expect(authService.changePassword(token, oldPass, '')).rejects.toThrow(domain_1.ValidationError);
        });
        it('should throw ValidationError if old and new passwords are the same', async () => {
            await expect(authService.changePassword(token, oldPass, oldPass)).rejects.toThrow(domain_1.ValidationError);
            await expect(authService.changePassword(token, oldPass, oldPass)).rejects.toThrow('New password cannot be the same as the old password.');
        });
        it('should re-throw operational errors from adapter', async () => {
            const authError = new domain_1.AuthenticationError('Incorrect old password'); // Assuming adapter maps NotAuthorizedException
            mockAuthAdapter_1.mockAuthAdapter.changePassword.mockRejectedValue(authError);
            await expect(authService.changePassword(token, 'wrongOld', newPass)).rejects.toThrow(domain_1.AuthenticationError);
            const validationError = new domain_1.ValidationError('Password policy failed'); // Assuming adapter maps InvalidPasswordException
            mockAuthAdapter_1.mockAuthAdapter.changePassword.mockRejectedValue(validationError);
            await expect(authService.changePassword(token, oldPass, 'weak')).rejects.toThrow(domain_1.ValidationError);
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledTimes(2);
        });
        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('Internal Cognito error');
            mockAuthAdapter_1.mockAuthAdapter.changePassword.mockRejectedValue(unexpectedError);
            await expect(authService.changePassword(token, oldPass, newPass)).rejects.toThrow(BaseError_1.BaseError); // Wraps as BaseError
            await expect(authService.changePassword(token, oldPass, newPass)).rejects.toThrow('Password change failed: Internal Cognito error');
            expect(mockLogger_1.mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Password change failed'), unexpectedError);
        });
    });
});
