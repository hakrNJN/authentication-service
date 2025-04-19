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
// TODO: Import authentication guard middleware when created
// import { authGuardMiddleware } from '../middlewares';

// Resolve dependencies
const authController = container.resolve(AuthController);
const logger = container.resolve<ILogger>(TYPES.Logger);

// Create router instance
const router = Router();

// --- Define Authentication Routes ---

// Signup & Confirmation
router.post('/signup', validationMiddleware(SignUpSchema, logger), authController.signUp);
router.post('/confirm-signup', validationMiddleware(ConfirmSignUpSchema, logger), authController.confirmSignUp);

// Login & MFA Verification
router.post('/login', validationMiddleware(LoginSchema, logger), authController.login);
router.post('/verify-mfa', validationMiddleware(VerifyMfaSchema, logger), authController.verifyMfa); // New route

// Refresh Token
router.post('/refresh', validationMiddleware(RefreshTokenSchema, logger), authController.refresh);

// Password Management
router.post('/forgot-password', validationMiddleware(ForgotPasswordSchema, logger), authController.forgotPassword);
router.post('/reset-password', validationMiddleware(ResetPasswordSchema, logger), authController.resetPassword);
// TODO: Apply authGuardMiddleware to '/change-password'
router.post(
    '/change-password',
    // authGuardMiddleware, // Apply guard
    validationMiddleware(ChangePasswordSchema, logger),
    authController.changePassword
);

// User Info & Logout
// TODO: Apply authGuardMiddleware to '/me' and '/logout'
router.get('/me', /* authGuardMiddleware, */ authController.getUserInfo);
router.post('/logout', /* authGuardMiddleware, */ authController.logout);

export default router;
