import { container } from 'tsyringe';
import { TYPES } from '../../../src/shared/constants/types';
import { IAuthAdapter } from '../../../src/application/interfaces/IAuthAdapter';
import { ILogger } from '../../../src/application/interfaces/ILogger';
import { IConfigService } from '../../../src/application/interfaces/IConfigService';
import { ITokenBlacklistService } from '../../../src/application/interfaces/ITokenBlacklistService';
import { IAuthService } from '../../../src/application/interfaces/IAuthService';
import { AuthService } from '../../../src/application/services/auth.service';
import { TokenBlacklistService } from '../../../src/application/services/TokenBlacklistService';
import { WinstonLogger } from '../../../src/infrastructure/logging/WinstonLogger';
import { EnvironmentConfigService } from '../../../src/infrastructure/config/EnvironmentConfigService';
import { MockCognitoAdapter } from './mockCognitoAdapter';

export function setupTestContainer(): void {
  // Clear existing registrations
  container.clearInstances();

  // Register services with mock adapter
  container.registerSingleton<ILogger>(TYPES.Logger, WinstonLogger);
  container.registerSingleton<IConfigService>(TYPES.ConfigService, EnvironmentConfigService);
  container.registerSingleton<ITokenBlacklistService>(TYPES.TokenBlacklistService, TokenBlacklistService);
  container.registerSingleton<IAuthService>(TYPES.AuthService, AuthService);
  
  // Use mock adapter for E2E tests
  container.registerSingleton<IAuthAdapter>(TYPES.AuthAdapter, MockCognitoAdapter);
}