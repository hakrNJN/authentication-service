# Design Document

## Overview

This design standardizes the Jest configuration to use `testPathPattern` for test filtering instead of the current mixed approach of `testMatch` in config files and `--testMatch` CLI overrides. The solution will simplify configuration management while maintaining all existing functionality and test execution capabilities.

## Architecture

### Current State Analysis
- **Main Jest Config (`jest.config.js`)**: Uses `testMatch: ['**/*.test.ts']` and `roots: ['<rootDir>/tests']`
- **E2E Jest Config (`jest.e2e.config.js`)**: Uses `testMatch: ['**/*.e2e.test.ts']` and `roots: ['<rootDir>/tests/e2e']`
- **Package.json Scripts**: Mix of CLI `--testMatch` overrides and separate config files

### Target State Design
- **Unified Test Pattern**: Single `testMatch` pattern that captures all test files
- **Path-Based Filtering**: Use `--testPathPattern` for targeting specific test directories
- **Simplified Configuration**: Remove redundant `testMatch` overrides in favor of path-based filtering

## Components and Interfaces

### Jest Configuration Files

#### Main Jest Configuration (`jest.config.js`)
```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  setupFilesAfterEnv: ['<rootDir>/tests/jest.setup.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  testMatch: ['**/*.test.ts'], // Unified pattern for all test files
  collectCoverageFrom: [
    'src/**/*.{ts,js}',
    '!src/main.ts',
    '!src/container.ts',
    '!src/**/index.ts',
    '!src/**/*.d.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov'],
  resetMocks: true,
  clearMocks: true,
  restoreMocks: true,
  maxWorkers: 1,
  forceExit: true,
  detectOpenHandles: true,
};
```

#### E2E Jest Configuration (`jest.e2e.config.js`)
```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  setupFilesAfterEnv: ['<rootDir>/tests/jest.setup.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  testMatch: ['**/*.test.ts'], // Unified pattern, filtering done via testPathPattern
  collectCoverageFrom: [
    'src/**/*.{ts,js}',
    '!src/main.ts',
    '!src/container.ts',
    '!src/**/index.ts',
    '!src/**/*.d.ts',
  ],
  coverageDirectory: 'coverage-e2e',
  coverageReporters: ['text', 'lcov'],
  resetMocks: true,
  clearMocks: true,
  restoreMocks: true,
  maxWorkers: 1,
  testTimeout: 30000,
  forceExit: true,
  detectOpenHandles: true,
};
```

### Package.json Script Updates

#### Test Scripts with testPathPattern
```json
{
  "scripts": {
    "test": "cross-env SHARED_SECRET=test-shared-secret REDIS_URL=redis://192.168.2.252:6379 USE_REDIS_BLACKLIST=true jest",
    "test:unit": "cross-env SHARED_SECRET=test-shared-secret REDIS_URL=redis://localhost:6379 USE_REDIS_BLACKLIST=true jest --testPathPattern=tests/unit",
    "test:integration": "cross-env SHARED_SECRET=test-shared-secret REDIS_URL=redis://192.168.2.252:6379 USE_REDIS_BLACKLIST=true jest --testPathPattern=tests/integration",
    "test:e2e": "cross-env SHARED_SECRET=test-shared-secret-e2e REDIS_URL=redis://192.168.2.252:6379 USE_REDIS_BLACKLIST=true jest --config jest.e2e.config.js --testPathPattern=tests/e2e",
    "test:coverage": "cross-env SHARED_SECRET=test-shared-secret REDIS_URL=redis://192.168.2.252:6379 USE_REDIS_BLACKLIST=true jest --coverage --testPathPattern=tests/unit",
    "test:integration:coverage": "cross-env SHARED_SECRET=test-shared-secret REDIS_URL=redis://192.168.2.252:6379 USE_REDIS_BLACKLIST=true jest --coverage --testPathPattern=tests/integration",
    "test:e2e:coverage": "cross-env SHARED_SECRET=test-shared-secret-e2e REDIS_URL=redis://192.168.2.252:6379 USE_REDIS_BLACKLIST=true jest --coverage --config jest.e2e.config.js --testPathPattern=tests/e2e",
    "test:all": "npm run test:unit && npm run test:integration && npm run test:e2e"
  }
}
```

## Data Models

### Test Path Patterns
- **Unit Tests**: `tests/unit` - Matches all files in the unit test directory
- **Integration Tests**: `tests/integration` - Matches all files in the integration test directory  
- **E2E Tests**: `tests/e2e` - Matches all files in the e2e test directory
- **All Tests**: No pattern specified - Matches all test files across all directories

### File Naming Conventions
- **Unit Tests**: `*.test.ts` files in `tests/unit/**`
- **Integration Tests**: `*.integration.test.ts` files in `tests/integration/`
- **E2E Tests**: `*.e2e.test.ts` files in `tests/e2e/`

## Error Handling

### Configuration Validation
- Ensure `testPathPattern` correctly targets intended directories
- Validate that all existing tests are still discoverable
- Confirm environment variables are properly passed to all test executions

### Backward Compatibility
- Maintain all existing Jest configuration options
- Preserve all environment variable configurations
- Keep separate e2e configuration for timeout and other e2e-specific settings

### Fallback Mechanisms
- If `testPathPattern` fails, Jest will fall back to the `testMatch` pattern
- All existing test files will remain discoverable through the unified `testMatch` pattern

## Testing Strategy

### Validation Approach
1. **Test Discovery Validation**: Run each script and verify correct test files are discovered
2. **Environment Variable Testing**: Confirm all environment variables are properly set for each test type
3. **Coverage Report Testing**: Verify coverage reports are generated correctly for each test suite
4. **Performance Testing**: Ensure test execution time is not negatively impacted

### Test Execution Verification
```bash
# Verify unit tests only
npm run test:unit

# Verify integration tests only  
npm run test:integration

# Verify e2e tests only
npm run test:e2e

# Verify all tests
npm test

# Verify coverage works for each type
npm run test:coverage
npm run test:integration:coverage
npm run test:e2e:coverage
```

### Success Criteria
- All test scripts execute without errors
- Each script targets only the intended test files
- Coverage reports are generated correctly
- No regression in test execution functionality
- Environment variables are properly configured for each test type