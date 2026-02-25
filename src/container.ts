import { container } from 'tsyringe';
import { TYPES } from './shared/constants/types';

// --- Import Interfaces (Ports) ---
import { IAuthAdapter } from './application/interfaces/IAuthAdapter';
import { IConfigService } from './application/interfaces/IConfigService';
import { ILogger } from './application/interfaces/ILogger';
import { ITokenBlacklistService } from './application/interfaces/ITokenBlacklistService';
// --- Import Implementations (Adapters/Services) ---
import { IAuthService } from './application/interfaces/IAuthService';
import { AuthService } from './application/services/auth.service';
import { TokenBlacklistService } from './application/services/TokenBlacklistService';
import { CognitoAuthAdapter } from './infrastructure/adapters/cognito/CognitoAuthAdapter';
import { EnvironmentConfigService } from './infrastructure/config/EnvironmentConfigService';
import { WinstonLogger } from './infrastructure/logging/WinstonLogger';
// import { AuthService } from './application/services/AuthService';

// --- Register Infrastructure Services (Singletons recommended) ---

// Logger Implementation (Winston)
// We register the concrete class directly, tsyringe handles instantiation.
// Or we can register an instance if custom setup is needed before registration.
container.registerSingleton<ILogger>(TYPES.Logger, WinstonLogger);

// Configuration Service Implementation
container.registerSingleton<IConfigService>(TYPES.ConfigService, EnvironmentConfigService);

// Event Bus Implementation
import { EventBusFactory } from './infrastructure/events/EventBusFactory';
container.registerSingleton(EventBusFactory);
container.register(TYPES.EventBus, {
    useFactory: () => {
        return EventBusFactory.createEventBus();
    }
});

// --- Register Adapters (Singletons usually appropriate) ---

// Universal Auth Strategy
import { CognitoAuthStrategy } from './infrastructure/adapters/cognito/CognitoAuthStrategy';
import { Auth0Strategy } from './infrastructure/adapters/auth0/Auth0Strategy';
import { FirebaseStrategy } from './infrastructure/adapters/firebase/FirebaseStrategy';
import { OktaStrategy } from './infrastructure/adapters/okta/OktaStrategy';
import { AuthStrategyFactory } from './infrastructure/factories/AuthStrategyFactory';

// Register Factory
container.registerSingleton(AuthStrategyFactory);
// Register Concrete Strategies
container.registerSingleton(CognitoAuthStrategy);
container.registerSingleton(Auth0Strategy);
container.registerSingleton(FirebaseStrategy);
container.registerSingleton(OktaStrategy);

// Register TYPES.AuthStrategy using the Factory
container.register(TYPES.AuthStrategy, {
    useFactory: (c) => {
        return c.resolve(AuthStrategyFactory).getStrategy();
    }
});

// --- Register Application Services (Scope depends on need - Singleton or Transient) ---

// Authentication Service
container.registerSingleton<IAuthService>(TYPES.AuthService, AuthService);
container.registerSingleton<ITokenBlacklistService>(TYPES.TokenBlacklistService, TokenBlacklistService);

// --- Register Controllers (Usually Transient - new instance per request) ---
// tsyringe typically handles controller resolution automatically if they are decorated
// with @injectable(), but you can register them explicitly if needed.


// Export the configured container
export { container };
