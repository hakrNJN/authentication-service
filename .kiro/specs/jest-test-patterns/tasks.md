# Implementation Plan

- [x] 1. Update main Jest configuration to use unified test pattern





  - Modify `jest.config.js` to use single `testMatch` pattern for all test files
  - Remove directory-specific `testMatch` patterns in favor of path-based filtering
  - _Requirements: 1.1, 2.1, 2.2_

- [x] 2. Update E2E Jest configuration to align with unified approach





  - Modify `jest.e2e.config.js` to use unified `testMatch` pattern
  - Update `roots` configuration to include all test directories
  - Maintain E2E-specific settings like timeout while standardizing test matching
  - _Requirements: 1.3, 2.1, 4.3_

- [x] 3. Update package.json test scripts to use testPathPattern





  - Replace `--testMatch` CLI overrides with `--testPathPattern` in unit test script
  - Replace `--testMatch` CLI overrides with `--testPathPattern` in integration test script  
  - Add `--testPathPattern` to E2E test script for consistency
  - Update all coverage scripts to use `--testPathPattern` instead of `--testMatch`
  - _Requirements: 1.2, 1.3, 2.2, 3.1, 3.2, 3.3, 3.4_

- [x] 4. Validate test discovery and execution





  - Run unit tests to verify only unit test files are executed
  - Run integration tests to verify only integration test files are executed
  - Run E2E tests to verify only E2E test files are executed
  - Run full test suite to verify all tests are discovered and executed
  - _Requirements: 1.1, 1.2, 1.3, 4.1, 4.4_

- [x] 5. Validate coverage functionality





  - Run unit test coverage to verify coverage reports are generated correctly
  - Run integration test coverage to verify coverage reports are generated correctly
  - Run E2E test coverage to verify coverage reports are generated correctly
  - Verify coverage collection settings are preserved across all test types
  - _Requirements: 3.4, 4.2, 4.4_

- [x] 6. Test environment variable preservation




  - Verify all environment variables are properly set for unit tests
  - Verify all environment variables are properly set for integration tests
  - Verify all environment variables are properly set for E2E tests
  - Confirm Redis URL and shared secret configurations work correctly
  - _Requirements: 4.1, 4.4_