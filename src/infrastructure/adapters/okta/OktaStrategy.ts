import { IAuthStrategy, AuthMode } from '../../../application/interfaces/IAuthStrategy';
import { AuthTokens, SignUpDetails, SignUpResult } from '../../../application/interfaces/IAuthAdapter';
import { AuthenticationError } from '../../../domain';

export class OktaStrategy implements IAuthStrategy {
    getAuthMode(): AuthMode {
        return 'CLIENT_SIDE'; // Can also be CREDENTIALS if using Okta Node SDK extensively
    }

    async login(): Promise<AuthTokens> {
        throw new Error('Okta login handled by client redirection (OIDC).');
    }

    async validateToken(token: string): Promise<any> {
        // TODO: Install '@okta/jwt-verifier'
        throw new AuthenticationError('Okta JWT Verifier not installed. Please install "@okta/jwt-verifier".');
    }

    async refreshToken(): Promise<AuthTokens> {
        throw new Error('Handled by Client (OIDC).');
    }

    // Stubs
    async respondToAuthChallenge(): Promise<AuthTokens> { throw new Error('Not supported'); }
    async getUserFromToken(): Promise<Record<string, any>> { throw new Error('Pending implementation'); }
    async signUp(): Promise<SignUpResult> { throw new Error('Handled by Okta Hosted UI'); }
    async confirmSignUp(): Promise<void> { throw new Error('Handled by Okta'); }
    async signOut(): Promise<void> { throw new Error('Handled by Client'); }
    async initiateForgotPassword(): Promise<any> { throw new Error('Handled by Okta'); }
    async confirmForgotPassword(): Promise<void> { throw new Error('Handled by Okta'); }
    async changePassword(): Promise<void> { throw new Error('Handled by Okta'); }

    async healthCheck(): Promise<boolean> {
        return true;
    }
}
