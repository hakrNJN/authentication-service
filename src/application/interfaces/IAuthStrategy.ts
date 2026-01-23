/**
 * Defines the contract for an Authentication Strategy.
 * This pattern allows switching between Credential-based (Cognito) and Client-based (Firebase/Auth0) flows.
 */
import { AuthTokens, SignUpDetails, SignUpResult } from './IAuthAdapter';
import { ChallengeNameType, CodeDeliveryDetailsType } from "@aws-sdk/client-cognito-identity-provider";

export type AuthMode = 'CREDENTIALS' | 'CLIENT_SIDE';

export interface IAuthStrategy {
    /**
     * returns 'CREDENTIALS' (backend handles password) 
     * or 'CLIENT_SIDE' (frontend handles login)
     */
    getAuthMode(): AuthMode;

    /**
     * Authenticates a user with username and password.
     * Only supported if getAuthMode() returns 'CREDENTIALS'.
     */
    login(username?: string, password?: string): Promise<AuthTokens>;

    /**
     * Validates a token provided by the client (for CLIENT_SIDE flow).
     * @param token The ID token from Firebase/Auth0
     */
    validateToken(token: string): Promise<any>;

    // MFA & Challenges
    respondToAuthChallenge(username: string, session: string, challengeName: ChallengeNameType, responses: Record<string, string>): Promise<AuthTokens>;

    // Token Management
    refreshToken(refreshToken: string): Promise<AuthTokens>;
    getUserFromToken(accessToken: string): Promise<Record<string, any>>;
    signOut(accessToken: string): Promise<void>;

    // User Management (Signup/Profile)
    signUp(details: SignUpDetails): Promise<SignUpResult>;
    confirmSignUp(username: string, code: string): Promise<void>;

    // Password Management
    initiateForgotPassword(username: string): Promise<CodeDeliveryDetailsType | undefined>;
    confirmForgotPassword(username: string, code: string, newPass: string): Promise<void>;
    changePassword(accessToken: string, oldPass: string, newPass: string): Promise<void>;
}
