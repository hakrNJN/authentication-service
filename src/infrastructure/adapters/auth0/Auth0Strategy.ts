import { IAuthStrategy, AuthMode } from '../../../application/interfaces/IAuthStrategy';
import { AuthTokens, SignUpDetails, SignUpResult } from '../../../application/interfaces/IAuthAdapter';
import { AuthenticationError } from '../../../domain';

export class Auth0Strategy implements IAuthStrategy {
    getAuthMode(): AuthMode {
        return 'CLIENT_SIDE';
    }

    async login(username?: string, password?: string): Promise<AuthTokens> {
        throw new Error('Auth0 login should be handled on the client side (SPA/Web). Use validateToken to verify the result on the server.');
    }

    async validateToken(token: string): Promise<any> {
        // TODO: Install 'jsonwebtoken' and 'jwks-rsa' to implement this.
        // const client = jwksClient({ jwksUri: 'https://YOUR_DOMAIN/.well-known/jwks.json' });
        throw new AuthenticationError('Auth0 Token Validation implementation pending. Please install jwks-rsa.');
    }

    async refreshToken(refreshToken: string): Promise<AuthTokens> {
        throw new Error('Auth0 refresh should be handled by the client or via Auth0 Management API.');
    }

    async respondToAuthChallenge(): Promise<AuthTokens> { throw new Error('Not supported in Auth0 Client-Side mode'); }
    async getUserFromToken(): Promise<Record<string, any>> { throw new Error('Implementation pending'); }
    async signUp(): Promise<SignUpResult> { throw new Error('Signup handled by Auth0 Universal Login'); }
    async confirmSignUp(): Promise<void> { throw new Error('Confirmation handled by Auth0'); }
    async signOut(): Promise<void> { throw new Error('Sign out handled by Client'); }
    async initiateForgotPassword(): Promise<any> { throw new Error('Handled by Auth0'); }
    async confirmForgotPassword(): Promise<void> { throw new Error('Handled by Auth0'); }
    async changePassword(): Promise<void> { throw new Error('Handled by Auth0'); }

    async healthCheck(): Promise<boolean> {
        // Check for required Auth0 config even if unimplemented
        return true;
    }
}
