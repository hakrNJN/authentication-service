import { container } from 'tsyringe';
import { TYPES } from './shared/constants/types';

// --- Import Interfaces (Ports) ---
import { IAuthAdapter } from './application/interfaces/IAuthAdapter';
import { IConfigService } from './application/interfaces/IConfigService';
import { ILogger } from './application/interfaces/ILogger';
// import { IAuthService } from './application/interfaces/IAuthService'; // Assuming this will exist

// --- Import Implementations (Adapters/Services) ---
// TODO: Create these implementation files
import { IAuthService } from './application/interfaces/IAuthService';
import { AuthService } from './application/services/auth.service';
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

// --- Register Adapters (Singletons usually appropriate) ---

// Cognito Adapter Implementation for IAuthAdapter interface
container.registerSingleton<IAuthAdapter>(TYPES.AuthAdapter, CognitoAuthAdapter);

// --- Register Application Services (Scope depends on need - Singleton or Transient) ---

// Authentication Service
container.registerSingleton<IAuthService>(TYPES.AuthService, AuthService); // Uncomment when AuthService exists

// --- Register Controllers (Usually Transient - new instance per request) ---
// tsyringe typically handles controller resolution automatically if they are decorated
// with @injectable(), but you can register them explicitly if needed.
// import { AuthController } from './api/controllers/auth.controller'; // Assuming this will exist
// container.register(TYPES.AuthController, { useClass: AuthController });


// Export the configured container
export { container };

