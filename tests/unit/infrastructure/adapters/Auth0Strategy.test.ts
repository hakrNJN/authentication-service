import 'reflect-metadata';
import { Auth0Strategy } from '../../../../src/infrastructure/adapters/auth0/Auth0Strategy';

describe('Auth0Strategy', () => {
    let strategy: Auth0Strategy;

    beforeEach(() => {
        strategy = new Auth0Strategy();
    });

    it('should return CLIENT_SIDE auth mode', () => {
        expect(strategy.getAuthMode()).toBe('CLIENT_SIDE');
    });

    it('login() should throw with client-side hint message', async () => {
        await expect(strategy.login('user', 'pass')).rejects.toThrow('client side');
    });

    it('validateToken() should throw with AuthenticationError', async () => {
        await expect(strategy.validateToken('some.jwt.token')).rejects.toThrow('Auth0 Token Validation');
    });

    it('refreshToken() should throw with Auth0 refresh message', async () => {
        await expect(strategy.refreshToken('refresh')).rejects.toThrow('Auth0 refresh');
    });

    it('respondToAuthChallenge() should throw', async () => {
        await expect(strategy.respondToAuthChallenge()).rejects.toThrow();
    });

    it('getUserFromToken() should throw', async () => {
        await expect(strategy.getUserFromToken()).rejects.toThrow();
    });

    it('signUp() should throw with Auth0 Universal Login message', async () => {
        await expect(strategy.signUp()).rejects.toThrow('Universal Login');
    });

    it('confirmSignUp() should throw', async () => {
        await expect(strategy.confirmSignUp()).rejects.toThrow('Auth0');
    });

    it('signOut() should throw', async () => {
        await expect(strategy.signOut()).rejects.toThrow();
    });

    it('initiateForgotPassword() should throw', async () => {
        await expect(strategy.initiateForgotPassword()).rejects.toThrow('Auth0');
    });

    it('confirmForgotPassword() should throw', async () => {
        await expect(strategy.confirmForgotPassword()).rejects.toThrow('Auth0');
    });

    it('changePassword() should throw', async () => {
        await expect(strategy.changePassword()).rejects.toThrow('Auth0');
    });

    it('healthCheck() should return true', async () => {
        await expect(strategy.healthCheck()).resolves.toBe(true);
    });
});
