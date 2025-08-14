import { Router } from 'express';
import { container } from '../../container';
import { AuthController } from '../controllers/auth.controller';
import { validationMiddleware } from '../middlewares/validation.middleware';
// Import Zod schemas
import { ILogger } from '../../application/interfaces/ILogger';
import { TYPES } from '../../shared/constants/types';
import {
    ChangePasswordSchema,
    ConfirmSignUpSchema,
    ForgotPasswordSchema,
    LoginSchema, RefreshTokenSchema,
    ResetPasswordSchema,
    SignUpSchema,
    VerifyMfaSchema // New schema import
} from '../dtos';
import { authGuardMiddleware } from '../middlewares/auth.guard.middleware';

// Resolve dependencies
const authController = container.resolve(AuthController);
const logger = container.resolve<ILogger>(TYPES.Logger);

// Create router instance
const router = Router();

// --- Define Authentication Routes ---

// Signup & Confirmation
router.post('/signup', validationMiddleware(SignUpSchema, logger), authController.signUp.bind(authController));
router.post('/confirm-signup', validationMiddleware(ConfirmSignUpSchema, logger), authController.confirmSignUp.bind(authController));

// Login & MFA Verification
router.post('/login', validationMiddleware(LoginSchema, logger), authController.login.bind(authController));
router.post('/verify-mfa', validationMiddleware(VerifyMfaSchema, logger), authController.verifyMfa.bind(authController)); // New route

// Refresh Token
router.post('/refresh-token', validationMiddleware(RefreshTokenSchema, logger), authController.refresh.bind(authController));

// Password Management
router.post('/forgot-password', validationMiddleware(ForgotPasswordSchema, logger), authController.forgotPassword.bind(authController));
router.post('/reset-password', validationMiddleware(ResetPasswordSchema, logger), authController.resetPassword.bind(authController));
// TODO: Apply authGuardMiddleware to '/change-password'
router.post(
    '/change-password',
    authGuardMiddleware(), // Apply guard
    validationMiddleware(ChangePasswordSchema, logger),
    authController.changePassword.bind(authController)
);

// User Info & Logout
// TODO: Apply authGuardMiddleware to '/me' and '/logout'
router.get('/me', authGuardMiddleware(), authController.getUserInfo.bind(authController));
router.post('/logout', authGuardMiddleware(), authController.signOut.bind(authController));

export default router;
