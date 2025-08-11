import { NextFunction, Request, Response } from 'express';
import { inject, injectable } from 'tsyringe';
import { IAuthService } from '../../application/interfaces/IAuthService';
import { ILogger } from '../../application/interfaces/ILogger';
import { TYPES } from '../../shared/constants/types';
// Import DTO types
import { AuthenticationError } from '../../domain';
import { ChangePasswordDto, ConfirmSignUpDto, ForgotPasswordDto, LoginDto, RefreshTokenDto, ResetPasswordDto, SignUpDto, VerifyMfaDto } from '../dtos';

@injectable()
export class AuthController {
    constructor(
        @inject(TYPES.AuthService) private authService: IAuthService,
        @inject(TYPES.Logger) private logger: ILogger
    ) { }

    // --- Existing Methods (login, refresh, getUserInfo, signUp, confirmSignUp, logout) ---
    // ... (Keep implementations as before) ...
    login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const loginDto = req.body as LoginDto;
            const tokens = await this.authService.login(loginDto.username, loginDto.password);
            res.status(200).json(tokens);
        } catch (error) { next(error); }
    };
    refresh = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const refreshTokenDto = req.body as RefreshTokenDto;
            const tokens = await this.authService.refresh(refreshTokenDto.refreshToken);
            res.status(200).json(tokens);
        } catch (error) { next(error); }
    };
    getUserInfo = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                throw new AuthenticationError('Authorization header missing or invalid');
            }
            const accessToken = authHeader.split(' ')[1];
            const userInfo = await this.authService.getUserInfo(accessToken);
            res.status(200).json(userInfo);
        } catch (error) { next(error); }
    };
    signUp = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const signUpDto = req.body as SignUpDto;
            const result = await this.authService.signUp(signUpDto);
            res.status(201).json(result);
        } catch (error) { next(error); }
    };
    confirmSignUp = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const confirmDto = req.body as ConfirmSignUpDto;
            await this.authService.confirmSignUp(confirmDto.username, confirmDto.confirmationCode);
            res.status(200).json({ message: 'Account confirmed successfully.' });
        } catch (error) { next(error); }
    };
    logout = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const accessToken = (req as any).user.accessToken; // Get token from user object
            await this.authService.logout(accessToken);
            res.status(204).send();
        } catch (error) { next(error); }
    };

    /**
      * Handles MFA verification requests.
      * POST /api/auth/verify-mfa
      */
    verifyMfa = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const verifyMfaDto = req.body as VerifyMfaDto;
            const tokens = await this.authService.verifyMfa(
                verifyMfaDto.username,
                verifyMfaDto.session,
                verifyMfaDto.challengeName, // Already validated as ChallengeNameType by Zod
                verifyMfaDto.code
            );
            // MFA verification successful, return tokens
            res.status(200).json(tokens);
        } catch (error) {
            // Handle specific errors like invalid code, session expiry, etc.
            next(error);
        }
    };

    /**
     * Handles forgot password requests.
     * POST /api/auth/forgot-password
     */
    forgotPassword = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const forgotPasswordDto = req.body as ForgotPasswordDto;
            const deliveryDetails = await this.authService.initiateForgotPassword(forgotPasswordDto.username);
            // Respond indicating where the code was sent (or just a generic success message)
            res.status(200).json({
                message: 'If a matching account was found, a password reset code has been sent.',
                // Optionally include deliveryDetails if safe to do so (e.g., masked email/phone)
                // deliveryDestination: deliveryDetails?.Destination,
                // deliveryMedium: deliveryDetails?.DeliveryMedium,
            });
        } catch (error) {
            // Don't reveal if user exists or not on error for forgot password
            // Log the actual error internally, but return a generic message
            // However, our adapter/service might throw specific errors we want to handle (like RateLimitError)
            if ((error as any)?.name === 'RateLimitError') {
                return next(error); // Pass specific errors like rate limiting
            }
            // Log the real error for debugging
            this.logger.error('Forgot password internal error:', error);
            // Return generic success to prevent user enumeration
            res.status(200).json({ message: 'If a matching account was found, a password reset code has been sent.' });
            // Or pass a generic internal error: next(new BaseError('ForgotPasswordFailed', 500, 'Failed to process forgot password request'));
        }
    };

    /**
     * Handles reset password requests using a confirmation code.
     * POST /api/auth/reset-password
     */
    resetPassword = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const resetPasswordDto = req.body as ResetPasswordDto;
            await this.authService.confirmForgotPassword(
                resetPasswordDto.username,
                resetPasswordDto.confirmationCode,
                resetPasswordDto.newPassword
            );
            res.status(200).json({ message: 'Password has been reset successfully.' });
        } catch (error) {
            next(error); // Pass specific errors (CodeMismatch, InvalidPassword, etc.)
        }
    };

    /**
     * Handles change password requests for authenticated users.
     * POST /api/auth/change-password
     * (Requires an authentication guard middleware)
     */
    changePassword = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            // Auth guard should verify token and potentially attach it or user info
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                throw new AuthenticationError('Authorization header missing or invalid');
            }
            const accessToken = authHeader.split(' ')[1]; // Extract token

            const changePasswordDto = req.body as ChangePasswordDto;
            await this.authService.changePassword(
                accessToken, // Pass token to service
                changePasswordDto.oldPassword,
                changePasswordDto.newPassword
            );
            res.status(200).json({ message: 'Password changed successfully.' });
        } catch (error) {
            next(error);
        }
    };
}
