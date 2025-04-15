// --- Export Exceptions ---
// Assuming BaseError is in shared, otherwise move/export from here

// export * from '../shared/errors/BaseError'; // Re-export BaseError if it stays in shared
export * from './exceptions/AuthenticationError';
// Export other custom domain exceptions here (e.g., AuthorizationError, DomainValidationError)
export { ValidationError } from '../shared/errors/BaseError';
// --- Export Entities ---
// Example: export * from './entities/User';
// Example: export * from './entities/Session';

// --- Export Value Objects ---
// Example: export * from './value-objects/Email';
// Example: export * from './value-objects/Password';

// --- Export Domain Services or Interfaces (if any) ---
// Example: export * from './services/PasswordHasher';

// --- Export Constants specific to the Domain ---
// Example: export * from './constants/userRoles';

