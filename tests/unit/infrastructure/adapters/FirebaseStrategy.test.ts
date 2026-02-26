import 'reflect-metadata';
import { FirebaseStrategy } from '../../../../src/infrastructure/adapters/firebase/FirebaseStrategy';

describe('FirebaseStrategy', () => {
    let strategy: FirebaseStrategy;

    beforeEach(() => {
        strategy = new FirebaseStrategy();
    });

    it('should return CLIENT_SIDE auth mode', () => {
        expect(strategy.getAuthMode()).toBe('CLIENT_SIDE');
    });

    it('login() should throw with client-side message', async () => {
        await expect(strategy.login()).rejects.toThrow('client side');
    });

    it('validateToken() should throw Firebase Admin SDK error', async () => {
        await expect(strategy.validateToken('token')).rejects.toThrow('Firebase Admin SDK');
    });

    it('refreshToken() should throw with client SDK message', async () => {
        await expect(strategy.refreshToken()).rejects.toThrow('client SDK');
    });

    it('respondToAuthChallenge() should throw', async () => {
        await expect(strategy.respondToAuthChallenge()).rejects.toThrow();
    });

    it('getUserFromToken() should throw', async () => {
        await expect(strategy.getUserFromToken()).rejects.toThrow();
    });

    it('signUp() should throw', async () => {
        await expect(strategy.signUp()).rejects.toThrow();
    });

    it('confirmSignUp() should throw', async () => {
        await expect(strategy.confirmSignUp()).rejects.toThrow();
    });

    it('signOut() should throw', async () => {
        await expect(strategy.signOut()).rejects.toThrow();
    });

    it('initiateForgotPassword() should throw', async () => {
        await expect(strategy.initiateForgotPassword()).rejects.toThrow();
    });

    it('confirmForgotPassword() should throw', async () => {
        await expect(strategy.confirmForgotPassword()).rejects.toThrow();
    });

    it('changePassword() should throw', async () => {
        await expect(strategy.changePassword()).rejects.toThrow();
    });

    it('healthCheck() should return true', async () => {
        await expect(strategy.healthCheck()).resolves.toBe(true);
    });
});
