/**
 * Defines unique symbols used as injection tokens for dependency injection (tsyringe).
 * Using symbols prevents potential naming conflicts with strings.
 */
export const TYPES = {
    // Application Layer Interfaces / Ports
    Logger: Symbol.for('Logger'),
    ConfigService: Symbol.for('ConfigService'),
    AuthService: Symbol.for('AuthService'), // Assuming an AuthService will exist
    AuthAdapter: Symbol.for('AuthAdapter'), // Interface for the IdP adapter
    TokenBlacklistService: Symbol.for('TokenBlacklistService'),

    // Universal Auth Tokens
    AuthStrategy: Symbol.for('AuthStrategy'),
    AuthStrategyFactory: Symbol.for('AuthStrategyFactory'),

    // Repository Factory
    RepositoryFactory: Symbol.for('RepositoryFactory'),

    // Add other service/adapter interfaces as needed

    // Infrastructure Layer Implementations (Usually not injected directly by type, but useful for registration)
    // Example: WinstonLogger: Symbol.for('WinstonLogger'),

    // API Layer (Controllers - if needed for complex DI scenarios, often resolved automatically by tsyringe)
    // Example: AuthController: Symbol.for('AuthController'),
};

