jest.mock('../../../../src/infrastructure/resilience/applyResilience', () => ({
    applyCircuitBreaker: (fn: any) => fn,
}));

import { ChallengeNameType, CodeDeliveryDetailsType, LimitExceededException } from '@aws-sdk/client-cognito-identity-provider';
import 'reflect-metadata'; // Required for tsyringe
import { AuthTokens, IAuthAdapter, SignUpResult } from '../../../../src/application/interfaces/IAuthAdapter';
import { IConfigService } from '../../../../src/application/interfaces/IConfigService';
import { ILogger } from '../../../../src/application/interfaces/ILogger';
import { AuthService } from '../../../../src/application/services/auth.service';
import { container } from '../../../../src/container';
import { AuthenticationError, MfaRequiredError, ValidationError } from '../../../../src/domain';
import { TYPES } from '../../../../src/shared/constants/types';
import { BaseError, NotFoundError } from '../../../../src/shared/errors/BaseError';
import { mockAuthAdapter } from '../../../mocks/mockAuthAdapter';
import { mockConfigService } from '../../../mocks/mockConfigService';
import { mockLogger } from '../../../mocks/mockLogger';



describe('AuthService', () => {
    let authService: AuthService;

    beforeEach(() => {
        jest.clearAllMocks();

        // Clear container instances and register mocks
        container.clearInstances();
        container.registerInstance<IAuthAdapter>(TYPES.AuthAdapter, mockAuthAdapter);
        container.registerInstance<ILogger>(TYPES.Logger, mockLogger);
        container.registerInstance<IConfigService>(TYPES.ConfigService, mockConfigService);

        authService = container.resolve(AuthService);
    });

    // --- Login ---
    describe('login', () => {
        it('should return tokens on successful login', async () => {
            const tokens: AuthTokens = { accessToken: 'a', refreshToken: 'r', expiresIn: 3600, tokenType: 'Bearer' };
            mockAuthAdapter.authenticateUser.mockResolvedValue(tokens);

            const result = await authService.login('user', 'pass');

            expect(result).toEqual(tokens);
            expect(mockAuthAdapter.authenticateUser).toHaveBeenCalledWith('user', 'pass');
            expect(mockLogger.info).toHaveBeenCalledWith('Login attempt for user: user');
            expect(mockLogger.info).toHaveBeenCalledWith('Login successful for user: user');
        });

        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.login('', 'pass')).rejects.toThrow(ValidationError);
            expect(mockAuthAdapter.authenticateUser).not.toHaveBeenCalled();
        });

        it('should throw ValidationError if password is missing', async () => {
            await expect(authService.login('user', '')).rejects.toThrow(ValidationError);
            expect(mockAuthAdapter.authenticateUser).not.toHaveBeenCalled();
        });

        it('should re-throw MfaRequiredError from adapter', async () => {
            const mfaError = new MfaRequiredError('sess', ChallengeNameType.SMS_MFA, {});
            mockAuthAdapter.authenticateUser.mockRejectedValue(mfaError);

            await expect(authService.login('user', 'pass')).rejects.toThrow(MfaRequiredError);
            expect(mockLogger.warn).toHaveBeenCalledWith(expect.stringContaining('MFA required for user user'));
        });

        it('should re-throw other operational errors from adapter', async () => {
            const authError = new AuthenticationError('Invalid credentials');
            mockAuthAdapter.authenticateUser.mockRejectedValue(authError);

            await expect(authService.login('user', 'pass')).rejects.toThrow(AuthenticationError);
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Login failed for user user'), expect.any(AuthenticationError));
        });

        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('Something broke');
            mockAuthAdapter.authenticateUser.mockRejectedValue(unexpectedError);

            await expect(authService.login('user', 'pass')).rejects.toThrow(AuthenticationError); // Wraps as AuthenticationError
            await expect(authService.login('user', 'pass')).rejects.toThrow('Login failed: Something broke');
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Login failed for user user'), unexpectedError);
        });
    });

    // --- Verify MFA ---
    describe('verifyMfa', () => {
        const username = 'user';
        const session = 'sess123';
        const code = '123456';
        const tokens: AuthTokens = { accessToken: 'a', refreshToken: 'r', expiresIn: 3600, tokenType: 'Bearer' };

        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.verifyMfa('', session, ChallengeNameType.SMS_MFA, code)).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if session is missing', async () => {
            await expect(authService.verifyMfa(username, '', ChallengeNameType.SMS_MFA, code)).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if challengeName is missing', async () => {
            await expect(authService.verifyMfa(username, session, '' as any, code)).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if code is missing', async () => {
            await expect(authService.verifyMfa(username, session, ChallengeNameType.SMS_MFA, '')).rejects.toThrow(ValidationError);
        });

        it('should call adapter with correct SMS_MFA responses and return tokens', async () => {
            mockAuthAdapter.respondToAuthChallenge.mockResolvedValue(tokens);
            const expectedResponses = { SMS_MFA_CODE: code, USERNAME: username };

            const result = await authService.verifyMfa(username, session, ChallengeNameType.SMS_MFA, code);

            expect(result).toEqual(tokens);
            expect(mockAuthAdapter.respondToAuthChallenge).toHaveBeenCalledWith(username, session, ChallengeNameType.SMS_MFA, expectedResponses);
            expect(mockLogger.info).toHaveBeenCalledWith(`Verifying MFA challenge ${ChallengeNameType.SMS_MFA} for user: ${username}`);
            expect(mockLogger.info).toHaveBeenCalledWith(`MFA verification successful for user: ${username}`);
        });

        it('should call adapter with correct SOFTWARE_TOKEN_MFA responses and return tokens', async () => {
            mockAuthAdapter.respondToAuthChallenge.mockResolvedValue(tokens);
            const expectedResponses = { SOFTWARE_TOKEN_MFA_CODE: code, USERNAME: username };

            const result = await authService.verifyMfa(username, session, ChallengeNameType.SOFTWARE_TOKEN_MFA, code);

            expect(result).toEqual(tokens);
            expect(mockAuthAdapter.respondToAuthChallenge).toHaveBeenCalledWith(username, session, ChallengeNameType.SOFTWARE_TOKEN_MFA, expectedResponses);
        });

        it('should call adapter with correct DEVICE_PASSWORD_VERIFIER responses and return tokens', async () => {
            mockAuthAdapter.respondToAuthChallenge.mockResolvedValue(tokens);
            const passkeyResponse = { id: 'deviceKey123', response: { signature: 'sig123' } };
            const passkeyCode = JSON.stringify(passkeyResponse);
            // Note: Timestamp will vary, so use expect.any(String) or mock Date
            const expectedResponses = expect.objectContaining({
                USERNAME: username,
                DEVICE_KEY: passkeyResponse.id,
                CHALLENGE_SIGNATURE: passkeyResponse.response.signature,
                TIMESTAMP: expect.any(String),
            });

            const result = await authService.verifyMfa(username, session, ChallengeNameType.DEVICE_PASSWORD_VERIFIER, passkeyCode);

            expect(result).toEqual(tokens);
            expect(mockAuthAdapter.respondToAuthChallenge).toHaveBeenCalledWith(username, session, ChallengeNameType.DEVICE_PASSWORD_VERIFIER, expectedResponses);
        });

        it('should throw ValidationError if DEVICE_PASSWORD_VERIFIER code is invalid JSON', async () => {
            const invalidJsonCode = '{ "id": "key", '; // Invalid JSON
            await expect(authService.verifyMfa(username, session, ChallengeNameType.DEVICE_PASSWORD_VERIFIER, invalidJsonCode)).rejects.toThrow(ValidationError);
            expect(mockAuthAdapter.respondToAuthChallenge).not.toHaveBeenCalled();
        });

        it('should throw ValidationError for unsupported challenge type', async () => {
            await expect(authService.verifyMfa(username, session, ChallengeNameType.CUSTOM_CHALLENGE, code)).rejects.toThrow(ValidationError);
            expect(mockAuthAdapter.respondToAuthChallenge).not.toHaveBeenCalled();
        });

        it('should re-throw operational errors from adapter', async () => {
            const authError = new AuthenticationError('Invalid code');
            mockAuthAdapter.respondToAuthChallenge.mockRejectedValue(authError);

            await expect(authService.verifyMfa(username, session, ChallengeNameType.SMS_MFA, code)).rejects.toThrow(AuthenticationError);
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('MFA verification failed'), authError);
        });

        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('Cognito down');
            mockAuthAdapter.respondToAuthChallenge.mockRejectedValue(unexpectedError);

            await expect(authService.verifyMfa(username, session, ChallengeNameType.SMS_MFA, code)).rejects.toThrow(AuthenticationError);
            await expect(authService.verifyMfa(username, session, ChallengeNameType.SMS_MFA, code)).rejects.toThrow('MFA verification failed: Cognito down');
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('MFA verification failed'), unexpectedError);
        });
    });

    // --- Refresh ---
    describe('refresh', () => {
        it('should return tokens on successful refresh', async () => {
            const tokens: AuthTokens = { accessToken: 'a', expiresIn: 3600, tokenType: 'Bearer' };
            mockAuthAdapter.refreshToken.mockResolvedValue(tokens);

            const result = await authService.refresh('old_refresh');

            expect(result).toEqual(tokens);
            expect(mockAuthAdapter.refreshToken).toHaveBeenCalledWith('old_refresh');
            expect(mockLogger.info).toHaveBeenCalledWith('Token refresh requested.');
            expect(mockLogger.info).toHaveBeenCalledWith('Token refresh successful.');
        });

        it('should throw ValidationError if refreshToken is missing', async () => {
            await expect(authService.refresh('')).rejects.toThrow(ValidationError);
            expect(mockAuthAdapter.refreshToken).not.toHaveBeenCalled();
        });

        it('should re-throw AuthenticationError from adapter', async () => {
            const authError = new AuthenticationError('Invalid token');
            mockAuthAdapter.refreshToken.mockRejectedValue(authError);

            await expect(authService.refresh('invalid_token')).rejects.toThrow(AuthenticationError);
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Token refresh failed'), authError);
        });

        it('should wrap non-AuthenticationError errors from adapter', async () => {
            const unexpectedError = new Error('Network issue');
            mockAuthAdapter.refreshToken.mockRejectedValue(unexpectedError);

            await expect(authService.refresh('valid_token')).rejects.toThrow(AuthenticationError);
            await expect(authService.refresh('valid_token')).rejects.toThrow('Token refresh failed: Network issue');
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Token refresh failed'), unexpectedError);
        });
    });

    // --- Get User Info ---
    describe('getUserInfo', () => {
        it('should return user info on success', async () => {
            const userInfo = { sub: 'uuid', email: 'test@example.com' };
            mockAuthAdapter.getUserFromToken.mockResolvedValue(userInfo);

            const result = await authService.getUserInfo('valid_token');

            expect(result).toEqual(userInfo);
            expect(mockAuthAdapter.getUserFromToken).toHaveBeenCalledWith('valid_token');
            expect(mockLogger.info).toHaveBeenCalledWith('Get user info requested.');
            expect(mockLogger.info).toHaveBeenCalledWith('Get user info successful.');
        });

        it('should throw ValidationError if accessToken is missing', async () => {
            await expect(authService.getUserInfo('')).rejects.toThrow(ValidationError);
            expect(mockAuthAdapter.getUserFromToken).not.toHaveBeenCalled();
        });

        it('should re-throw AuthenticationError from adapter', async () => {
            const authError = new AuthenticationError('Invalid token');
            mockAuthAdapter.getUserFromToken.mockRejectedValue(authError);

            await expect(authService.getUserInfo('invalid_token')).rejects.toThrow(AuthenticationError);
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Get user info failed'), authError);
        });

        it('should wrap non-AuthenticationError errors from adapter', async () => {
            const unexpectedError = new Error('Cognito issue');
            mockAuthAdapter.getUserFromToken.mockRejectedValue(unexpectedError);

            await expect(authService.getUserInfo('valid_token')).rejects.toThrow(AuthenticationError);
            await expect(authService.getUserInfo('valid_token')).rejects.toThrow('Failed to retrieve user info: Cognito issue');
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Get user info failed'), unexpectedError);
        });
    });

    // --- Sign Up ---
    describe('signUp', () => {
        const details = { username: 'newuser', password: 'password123', attributes: { email: 'new@example.com' } };
        const result: SignUpResult = { userSub: 'uuid', userConfirmed: false };

        it('should return signup result on success', async () => {
            mockAuthAdapter.signUp.mockResolvedValue(result);

            const response = await authService.signUp(details);

            expect(response).toEqual(result);
            expect(mockAuthAdapter.signUp).toHaveBeenCalledWith(details);
            expect(mockLogger.info).toHaveBeenCalledWith(`Signup attempt for username: ${details.username}`);
            expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining(`Signup successful for ${details.username}`));
        });

        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.signUp({ ...details, username: '' })).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if password is missing', async () => {
            await expect(authService.signUp({ ...details, password: '' })).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if email attribute is missing', async () => {
            await expect(authService.signUp({ ...details, attributes: {} })).rejects.toThrow(ValidationError);
        });

        it('should re-throw operational errors from adapter', async () => {
            const validationError = new ValidationError('Username already exists.');
            mockAuthAdapter.signUp.mockRejectedValue(validationError);

            await expect(authService.signUp(details)).rejects.toThrow(ValidationError);
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Signup failed'), validationError);
        });

        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('AWS down');
            mockAuthAdapter.signUp.mockRejectedValue(unexpectedError);

            await expect(authService.signUp(details)).rejects.toThrow(BaseError); // Wraps as BaseError
            await expect(authService.signUp(details)).rejects.toThrow('Signup failed: AWS down');
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Signup failed'), unexpectedError);
        });
    });

    // --- Confirm Sign Up ---
    describe('confirmSignUp', () => {
        it('should complete successfully', async () => {
            mockAuthAdapter.confirmSignUp.mockResolvedValue(undefined);

            await expect(authService.confirmSignUp('user', '123456')).resolves.toBeUndefined();
            expect(mockAuthAdapter.confirmSignUp).toHaveBeenCalledWith('user', '123456');
            expect(mockLogger.info).toHaveBeenCalledWith('Attempting signup confirmation for: user');
            expect(mockLogger.info).toHaveBeenCalledWith('Signup confirmed for: user');
        });

        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.confirmSignUp('', '123456')).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if confirmationCode is missing', async () => {
            await expect(authService.confirmSignUp('user', '')).rejects.toThrow(ValidationError);
        });

        it('should re-throw known errors (Auth, NotFound) from adapter', async () => {
            const authError = new AuthenticationError('Code mismatch');
            mockAuthAdapter.confirmSignUp.mockRejectedValue(authError);
            await expect(authService.confirmSignUp('user', 'wrong')).rejects.toThrow(AuthenticationError);

            const notFoundError = new NotFoundError('User');
            mockAuthAdapter.confirmSignUp.mockRejectedValue(notFoundError);
            await expect(authService.confirmSignUp('user', '123')).rejects.toThrow(NotFoundError);

            expect(mockLogger.error).toHaveBeenCalledTimes(2);
        });

        it('should wrap unexpected errors from adapter', async () => {
            const unexpectedError = new Error('Network glitch');
            mockAuthAdapter.confirmSignUp.mockRejectedValue(unexpectedError);

            await expect(authService.confirmSignUp('user', '123')).rejects.toThrow(AuthenticationError); // Wraps as Auth Error
            await expect(authService.confirmSignUp('user', '123')).rejects.toThrow('Confirmation failed: Network glitch');
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Signup confirmation failed'), unexpectedError);
        });
    });

    // --- SignOut ---
    describe('signOut', () => {
        it('should complete successfully', async () => {
            mockAuthAdapter.signOut.mockResolvedValue(undefined);

            await expect(authService.signOut('valid_token')).resolves.toBeUndefined();
            expect(mockAuthAdapter.signOut).toHaveBeenCalledWith('valid_token');
            expect(mockLogger.info).toHaveBeenCalledWith('Logout requested.');
            expect(mockLogger.info).toHaveBeenCalledWith('Logout successful.');
        });

        it('should throw ValidationError if accessToken is missing', async () => {
            await expect(authService.signOut('')).rejects.toThrow(ValidationError);
        });

        it('should re-throw AuthenticationError from adapter', async () => {
            const authError = new AuthenticationError('Invalid token');
            mockAuthAdapter.signOut.mockRejectedValue(authError);

            await expect(authService.signOut('invalid')).rejects.toThrow(AuthenticationError);
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Logout failed'), authError);
        });

        it('should wrap unexpected errors from adapter', async () => {
            const unexpectedError = new Error('Server issue');
            mockAuthAdapter.signOut.mockRejectedValue(unexpectedError);

            await expect(authService.signOut('valid')).rejects.toThrow(AuthenticationError); // Wraps as Auth Error
            await expect(authService.signOut('valid')).rejects.toThrow('Logout failed: Server issue');
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Logout failed'), unexpectedError);
        });
    });

    // --- Initiate Forgot Password ---
    describe('initiateForgotPassword', () => {
        const username = 'user';
        const deliveryDetails: CodeDeliveryDetailsType = { Destination: 'a***@b.com', DeliveryMedium: 'EMAIL', AttributeName: 'email' };

        it('should return delivery details on success', async () => {
            mockAuthAdapter.initiateForgotPassword.mockResolvedValue(deliveryDetails);

            const result = await authService.initiateForgotPassword(username);

            expect(result).toEqual(deliveryDetails);
            expect(mockAuthAdapter.initiateForgotPassword).toHaveBeenCalledWith(username);
            expect(mockLogger.info).toHaveBeenCalledWith(`Initiating forgot password process for user: ${username}`);
            expect(mockLogger.info).toHaveBeenCalledWith(`Forgot password initiated for ${username}.`);
        });

        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.initiateForgotPassword('')).rejects.toThrow(ValidationError);
        });

        it('should re-throw operational errors from adapter', async () => {
            const notFoundError = new NotFoundError('User'); // Example operational error
            mockAuthAdapter.initiateForgotPassword.mockRejectedValue(notFoundError);

            await expect(authService.initiateForgotPassword(username)).rejects.toThrow(NotFoundError);
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Initiate forgot password failed'), notFoundError);
        });

        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('SES issue');
            mockAuthAdapter.initiateForgotPassword.mockRejectedValue(unexpectedError);

            await expect(authService.initiateForgotPassword(username)).rejects.toThrow(BaseError); // Wraps as BaseError
            await expect(authService.initiateForgotPassword(username)).rejects.toThrow('Forgot password initiation failed: SES issue');
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Initiate forgot password failed'), unexpectedError);
        });
    });

    // --- Confirm Forgot Password ---
    describe('confirmForgotPassword', () => {
        const username = 'user';
        const code = '123456';
        const newPassword = 'NewPassword123!';

        it('should complete successfully', async () => {
            mockAuthAdapter.confirmForgotPassword.mockResolvedValue(undefined);

            await expect(authService.confirmForgotPassword(username, code, newPassword)).resolves.toBeUndefined();
            expect(mockAuthAdapter.confirmForgotPassword).toHaveBeenCalledWith(username, code, newPassword);
            expect(mockLogger.info).toHaveBeenCalledWith(`Confirming forgot password for user: ${username}`);
            expect(mockLogger.info).toHaveBeenCalledWith(`Password reset successfully for user: ${username}`);
        });

        it('should throw ValidationError if username is missing', async () => {
            await expect(authService.confirmForgotPassword('', code, newPassword)).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if code is missing', async () => {
            await expect(authService.confirmForgotPassword(username, '', newPassword)).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if newPassword is missing', async () => {
            await expect(authService.confirmForgotPassword(username, code, '')).rejects.toThrow(ValidationError);
        });

        it('should re-throw operational errors from adapter', async () => {
            // Use actual Cognito exceptions if adapter maps them, or domain errors
            const codeMismatch = new AuthenticationError('Code mismatch'); // Assuming adapter maps CodeMismatchException
            mockAuthAdapter.confirmForgotPassword.mockRejectedValue(codeMismatch);
            await expect(authService.confirmForgotPassword(username, 'wrong', newPassword)).rejects.toThrow(AuthenticationError);

            const limitExceeded = new LimitExceededException({ $metadata: {}, message: 'Limit exceeded' }); // Raw SDK exception
            mockAuthAdapter.confirmForgotPassword.mockRejectedValue(limitExceeded);
            await expect(authService.confirmForgotPassword(username, code, newPassword)).rejects.toThrow(LimitExceededException);

            expect(mockLogger.error).toHaveBeenCalledTimes(2);
        });

        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('DB connection failed');
            mockAuthAdapter.confirmForgotPassword.mockRejectedValue(unexpectedError);

            await expect(authService.confirmForgotPassword(username, code, newPassword)).rejects.toThrow(BaseError); // Wraps as BaseError
            await expect(authService.confirmForgotPassword(username, code, newPassword)).rejects.toThrow('Password reset confirmation failed: DB connection failed');
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Confirm forgot password failed'), unexpectedError);
        });
    });

    // --- Change Password ---
    describe('changePassword', () => {
        const token = 'valid_token';
        const oldPass = 'OldPassword123';
        const newPass = 'NewPassword456!';

        it('should complete successfully', async () => {
            mockAuthAdapter.changePassword.mockResolvedValue(undefined);

            await expect(authService.changePassword(token, oldPass, newPass)).resolves.toBeUndefined();
            expect(mockAuthAdapter.changePassword).toHaveBeenCalledWith(token, oldPass, newPass);
            expect(mockLogger.info).toHaveBeenCalledWith('Attempting password change for authenticated user.');
            expect(mockLogger.info).toHaveBeenCalledWith('Password changed successfully for the user.');
        });

        it('should throw ValidationError if token is missing', async () => {
            await expect(authService.changePassword('', oldPass, newPass)).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if oldPassword is missing', async () => {
            await expect(authService.changePassword(token, '', newPass)).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if newPassword is missing', async () => {
            await expect(authService.changePassword(token, oldPass, '')).rejects.toThrow(ValidationError);
        });
        it('should throw ValidationError if old and new passwords are the same', async () => {
            await expect(authService.changePassword(token, oldPass, oldPass)).rejects.toThrow(ValidationError);
            await expect(authService.changePassword(token, oldPass, oldPass)).rejects.toThrow('New password cannot be the same as the old password.');
        });

        it('should re-throw operational errors from adapter', async () => {
            const authError = new AuthenticationError('Incorrect old password'); // Assuming adapter maps NotAuthorizedException
            mockAuthAdapter.changePassword.mockRejectedValue(authError);
            await expect(authService.changePassword(token, 'wrongOld', newPass)).rejects.toThrow(AuthenticationError);

            const validationError = new ValidationError('Password policy failed'); // Assuming adapter maps InvalidPasswordException
            mockAuthAdapter.changePassword.mockRejectedValue(validationError);
            await expect(authService.changePassword(token, oldPass, 'weak')).rejects.toThrow(ValidationError);

            expect(mockLogger.error).toHaveBeenCalledTimes(2);
        });

        it('should wrap non-operational errors from adapter', async () => {
            const unexpectedError = new Error('Internal Cognito error');
            mockAuthAdapter.changePassword.mockRejectedValue(unexpectedError);

            await expect(authService.changePassword(token, oldPass, newPass)).rejects.toThrow(BaseError); // Wraps as BaseError
            await expect(authService.changePassword(token, oldPass, newPass)).rejects.toThrow('Password change failed: Internal Cognito error');
            expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Password change failed'), unexpectedError);
        });
    });

});