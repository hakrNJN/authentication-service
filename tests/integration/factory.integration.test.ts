
import 'reflect-metadata';
import { container } from 'tsyringe';
import { AuthStrategyFactory } from '../../src/infrastructure/factories/AuthStrategyFactory';
import { CognitoAuthStrategy } from '../../src/infrastructure/adapters/cognito/CognitoAuthStrategy';
import { Auth0Strategy } from '../../src/infrastructure/adapters/auth0/Auth0Strategy';
import { FirebaseStrategy } from '../../src/infrastructure/adapters/firebase/FirebaseStrategy';
import { OktaStrategy } from '../../src/infrastructure/adapters/okta/OktaStrategy';
import { IConfigService } from '../../src/application/interfaces/IConfigService';
import { TYPES } from '../../src/shared/constants/types';

describe('AuthStrategyFactory Integration', () => {
    let factory: AuthStrategyFactory;
    let mockConfigService: any;

    let mockCognitoStrategy: any;
    let mockAuth0Strategy: any;
    let mockFirebaseStrategy: any;
    let mockOktaStrategy: any;

    beforeEach(() => {
        container.clearInstances();
        mockConfigService = {
            get: jest.fn(),
            getOrThrow: jest.fn()
        };

        mockCognitoStrategy = { name: 'Cognito' };
        mockAuth0Strategy = { name: 'Auth0' };
        mockFirebaseStrategy = { name: 'Firebase' };
        mockOktaStrategy = { name: 'Okta' };

        container.registerInstance(TYPES.ConfigService, mockConfigService);
        container.registerInstance(CognitoAuthStrategy, mockCognitoStrategy);
        container.registerInstance(Auth0Strategy, mockAuth0Strategy);
        container.registerInstance(FirebaseStrategy, mockFirebaseStrategy);
        container.registerInstance(OktaStrategy, mockOktaStrategy);

        factory = container.resolve(AuthStrategyFactory);
    });

    it('should resolve CognitoAuthStrategy when AUTH_PROVIDER is COGNITO', () => {
        mockConfigService.get.mockImplementation((key: string) => {
            if (key === 'AUTH_PROVIDER') return 'COGNITO';
            return undefined;
        });

        const strategy = factory.getStrategy(); // Use getStrategy, not createStrategy
        expect(strategy).toBe(mockCognitoStrategy);
    });

    it('should resolve Auth0Strategy when AUTH_PROVIDER is AUTH0', () => {
        mockConfigService.get.mockImplementation((key: string) => {
            if (key === 'AUTH_PROVIDER') return 'AUTH0';
            return undefined;
        });

        const strategy = factory.getStrategy();
        expect(strategy).toBe(mockAuth0Strategy);
    });

    it('should resolve FirebaseStrategy when AUTH_PROVIDER is FIREBASE', () => {
        mockConfigService.get.mockImplementation((key: string) => {
            if (key === 'AUTH_PROVIDER') return 'FIREBASE';
            return undefined;
        });

        const strategy = factory.getStrategy();
        expect(strategy).toBe(mockFirebaseStrategy);
    });
});
