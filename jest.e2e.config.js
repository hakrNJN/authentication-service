module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  setupFilesAfterEnv: ['<rootDir>/tests/jest.setup.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  testMatch: ['**/*.test.ts'],
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
  maxWorkers: 1, // Force running in a single process
  testTimeout: 30000, // 30 seconds timeout for E2E tests
  forceExit: true, // Force Jest to exit after tests complete
  detectOpenHandles: true, // Help detect what's keeping Jest open
};