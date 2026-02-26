import 'reflect-metadata';
import { OktaStrategy } from '../../../../src/infrastructure/adapters/okta/OktaStrategy';

describe('OktaStrategy', () => {
    let strategy: OktaStrategy;

    beforeEach(() => {
        strategy = new OktaStrategy();
    });

    it('should return CLIENT_SIDE auth mode', () => {
        expect(strategy.getAuthMode()).toBe('CLIENT_SIDE');
    });

    it('login() should throw with OIDC message', async () => {
        await expect(strategy.login()).rejects.toThrow('Okta login handled by client');
    });

    it('validateToken() should throw with Okta JWT Verifier message', async () => {
        await expect(strategy.validateToken('token')).rejects.toThrow('Okta JWT Verifier');
    });

    it('refreshToken() should throw with OIDC message', async () => {
        await expect(strategy.refreshToken()).rejects.toThrow('OIDC');
    });

    it('respondToAuthChallenge() should throw', async () => {
        await expect(strategy.respondToAuthChallenge()).rejects.toThrow();
    });

    it('getUserFromToken() should throw', async () => {
        await expect(strategy.getUserFromToken()).rejects.toThrow();
    });

    it('signUp() should throw', async () => {
        await expect(strategy.signUp()).rejects.toThrow('Okta');
    });

    it('confirmSignUp() should throw', async () => {
        await expect(strategy.confirmSignUp()).rejects.toThrow('Okta');
    });

    it('signOut() should throw', async () => {
        await expect(strategy.signOut()).rejects.toThrow();
    });

    it('initiateForgotPassword() should throw', async () => {
        await expect(strategy.initiateForgotPassword()).rejects.toThrow('Okta');
    });

    it('confirmForgotPassword() should throw', async () => {
        await expect(strategy.confirmForgotPassword()).rejects.toThrow('Okta');
    });

    it('changePassword() should throw', async () => {
        await expect(strategy.changePassword()).rejects.toThrow('Okta');
    });

    it('healthCheck() should return true', async () => {
        await expect(strategy.healthCheck()).resolves.toBe(true);
    });
});
