import { IAuthStrategy, AuthMode } from '../../../application/interfaces/IAuthStrategy';
import { AuthTokens, SignUpDetails, SignUpResult } from '../../../application/interfaces/IAuthAdapter';
import { AuthenticationError } from '../../../domain';

export class FirebaseStrategy implements IAuthStrategy {
    getAuthMode(): AuthMode {
        return 'CLIENT_SIDE';
    }

    async login(): Promise<AuthTokens> {
        throw new Error('Firebase login is handled on the client side. Send the ID Token to the server for validation.');
    }

    async validateToken(token: string): Promise<any> {
        // TODO: Install 'firebase-admin'
        // await firebaseAdmin.auth().verifyIdToken(token);
        throw new AuthenticationError('Firebase Admin SDK not installed. Please install "firebase-admin".');
    }

    async refreshToken(): Promise<AuthTokens> {
        throw new Error('Firebase token refresh is handled by the client SDK.');
    }

    // Stubs
    async respondToAuthChallenge(): Promise<AuthTokens> { throw new Error('Not supported'); }
    async getUserFromToken(): Promise<Record<string, any>> { throw new Error('Pending implementation (use firebase-admin)'); }
    async signUp(): Promise<SignUpResult> { throw new Error('Handled by Client SDK'); }
    async confirmSignUp(): Promise<void> { throw new Error('Handled by Client SDK'); }
    async signOut(): Promise<void> { throw new Error('Handled by Client SDK'); }
    async initiateForgotPassword(): Promise<any> { throw new Error('Handled by Client SDK'); }
    async confirmForgotPassword(): Promise<void> { throw new Error('Handled by Client SDK'); }
    async changePassword(): Promise<void> { throw new Error('Handled by Client SDK'); }

    async healthCheck(): Promise<boolean> {
        return true;
    }
}
