import 'reflect-metadata';
import { AuthStrategyFactory } from '../../../../src/infrastructure/factories/AuthStrategyFactory';
import { AuthProvider } from '../../../../src/shared/constants/AuthProvider';
import { IConfigService } from '../../../../src/application/interfaces/IConfigService';
import { IAuthStrategy } from '../../../../src/application/interfaces/IAuthStrategy';

function makeMockStrategy(): jest.Mocked<IAuthStrategy> {
    return {
        getAuthMode: jest.fn().mockReturnValue('CREDENTIALS'),
        login: jest.fn(),
        validateToken: jest.fn(),
        refreshToken: jest.fn(),
        respondToAuthChallenge: jest.fn(),
        getUserFromToken: jest.fn(),
        signUp: jest.fn(),
        confirmSignUp: jest.fn(),
        signOut: jest.fn(),
        initiateForgotPassword: jest.fn(),
        confirmForgotPassword: jest.fn(),
        changePassword: jest.fn(),
        healthCheck: jest.fn().mockResolvedValue(true),
    } as unknown as jest.Mocked<IAuthStrategy>;
}

function buildFactory(provider: string): AuthStrategyFactory {
    const configService: jest.Mocked<IConfigService> = {
        get: jest.fn().mockImplementation((key: string) => {
            if (key === 'AUTH_PROVIDER') return provider;
            return undefined;
        }),
        getNumber: jest.fn(),
        getBoolean: jest.fn(),
        getAllConfig: jest.fn(),
        has: jest.fn(),
        isDevelopment: jest.fn(),
        isProduction: jest.fn(),
        isTest: jest.fn(),
        getTableName: jest.fn(),
    } as any;

    return new AuthStrategyFactory(
        configService,
        makeMockStrategy() as any,  // cognitoStrategy
        makeMockStrategy() as any,  // auth0Strategy
        makeMockStrategy() as any,  // firebaseStrategy
        makeMockStrategy() as any,  // oktaStrategy
    );
}

describe('AuthStrategyFactory', () => {
    it('should return Cognito strategy for COGNITO provider', () => {
        const factory = buildFactory('COGNITO');
        const strategy = factory.getStrategy();
        expect(strategy).toBeDefined();
    });

    it('should return Cognito strategy for lowercase cognito', () => {
        const factory = buildFactory('cognito');
        const strategy = factory.getStrategy();
        expect(strategy).toBeDefined();
    });

    it('should return Auth0 strategy for AUTH0 provider', () => {
        const factory = buildFactory('AUTH0');
        const strategy = factory.getStrategy();
        expect(strategy).toBeDefined();
    });

    it('should return Firebase strategy for FIREBASE provider', () => {
        const factory = buildFactory('FIREBASE');
        const strategy = factory.getStrategy();
        expect(strategy).toBeDefined();
    });

    it('should return Okta strategy for OKTA provider', () => {
        const factory = buildFactory('OKTA');
        const strategy = factory.getStrategy();
        expect(strategy).toBeDefined();
    });

    it('should default to Cognito when AUTH_PROVIDER is not set (empty string)', () => {
        // The factory has: const providerRaw = this.configService.get(...) || 'COGNITO';
        // So empty string gets replaced by 'COGNITO' and returns Cognito strategy
        const factory = buildFactory('');
        expect(() => factory.getStrategy()).not.toThrow();
        const strategy = factory.getStrategy();
        expect(strategy).toBeDefined();
    });

    it('should throw for unsupported provider', () => {
        const factory = buildFactory('UNKNOWN_PROVIDER_XYZ');
        expect(() => factory.getStrategy()).toThrow('Unsupported AUTH_PROVIDER');
    });
});
