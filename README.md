# Authentication Service

## Overview & Purpose

This microservice acts as the central hub for user authentication and related identity operations within the broader application architecture. Its primary responsibilities include verifying user credentials, issuing and refreshing access tokens, handling user registration and confirmation, and managing user-facing password flows (forgot/reset password).

## Prerequisites

- Node.js (Check `package.json` for specific version requirements if any)
- pnpm (Package manager used: `pnpm@10.9.0`)

## Installation

1.  Clone the repository:
    ```bash
    git clone <repository-url>
    cd authentication-service
    ```
2.  Install dependencies:
    ```bash
    pnpm install
    ```

## Configuration

1.  Copy the example environment file:
    ```bash
    cp .env.example .env
    ```
2.  Update the `.env` file with your specific configuration values (e.g., AWS credentials, Cognito details, DynamoDB endpoint). Refer to `config/default.yml` and `src/infrastructure/config/EnvironmentConfigService.ts` for required variables. Configuration is loaded using the Node.js `--env-file` flag.

## Running the Application

### Development Mode

Runs the application using `ts-node-dev` with file watching and hot-reloading. Uses `.env.example` for environment variables.

```bash
pnpm run dev
```

### Production Mode

Builds the TypeScript code to JavaScript and runs the compiled code using Node.js. Requires a configured `.env` file.

```bash
pnpm run build
pnpm run start
```

## Running Tests

Execute the test suite using Jest:

```bash
pnpm run test
```

## Technology Stack

- **Backend:** Node.js, TypeScript
- **Web Framework:** Express.js
- **Dependency Injection:** tsyringe
- **Identity Provider (IdP):** AWS Cognito (abstracted via Adapter)
- **Logging:** Winston (with conditional CloudWatch integration for production)
- **Validation:** Zod (for API DTOs)
- **Resilience:** opossum (Circuit Breaker pattern)
- **Configuration:** Node.js `--env-file` flag for environment variables
- **Package Manager:** pnpm
- **Testing:** Jest, Supertest, `aws-sdk-client-mock`
- **Linting/Formatting:** ESLint, Prettier

## Architecture & Design

- **Layered Architecture:** Strictly follows a layered approach separating concerns into:
    - **API Layer:** Handles HTTP requests/responses, routing (Express), DTO validation (Zod), and middleware.
    - **Application Layer:** Contains core business logic orchestration (Services), defines contracts for external dependencies (Interfaces/Ports).
    - **Domain Layer:** Encapsulates core domain concepts and custom exceptions (e.g., AuthenticationError subtypes).
    - **Infrastructure Layer:** Implements external concerns like IdP interaction (Cognito Adapter), logging (Winston), configuration loading, and resilience patterns.
- **API First Design:** API contracts are defined upfront using DTOs and validated using middleware.
- **Design Patterns:** Leverages several key patterns:
    - **Dependency Injection (DI):** Managed by tsyringe for loose coupling and testability.
    - **Adapter Pattern:** Used extensively (e.g., `IAuthAdapter`/`CognitoAuthAdapter`) to abstract the specific IdP, enabling provider agnosticism.
    - **Service Layer:** Centralizes application logic.
    - **Middleware Pattern:** Used within Express for request processing (validation, error handling, etc.).
    - **Repository Pattern (Implied):** Although not heavily used yet, the structure supports adding repositories for data persistence.
    - **Circuit Breaker:** Implemented using opossum via a helper function (`applyCircuitBreaker`) for resilient external calls.
- **SOLID Principles:** The architecture promotes adherence to SOLID principles for maintainability and scalability.

## Key Features Implemented

- User Login (Password-based)
- Access Token Refresh
- User Signup & Confirmation
- User Logout (Global Sign-Out)
- User-Facing Password Management (Forgot Password, Reset Password)
- Basic Server Health & Info Endpoints
- Structured Logging (Console & CloudWatch)
- Configuration via Environment Files
- Centralized Error Handling
- Input Validation (DTOs)
- Circuit Breaker for IdP calls

## Project Structure Overview

```
authentication-service/
├── config/               # Application configuration files (e.g., default.yml)
├── src/                  # Source code
│   ├── api/              # API layer (Controllers, Routes, Middlewares, DTOs)
│   ├── application/      # Application core logic (Services, Use Cases, Interfaces)
│   ├── domain/           # Domain entities, value objects, exceptions
│   ├── infrastructure/   # Infrastructure concerns (Adapters, Config, Logging, Persistence)
│   ├── shared/           # Shared utilities, constants, types
│   ├── app.ts            # Express application setup
│   ├── container.ts      # Dependency injection container setup (tsyringe)
│   └── main.ts           # Application entry point
├── tests/                # Automated tests (unit, integration, e2e)
├── .env.example          # Example environment variables
├── .eslintrc.js          # ESLint configuration
├── .gitignore            # Git ignore rules
├── Dockerfile            # Docker configuration
├── jest.config.js        # Jest test runner configuration
├── package.json          # Project metadata and dependencies
├── pnpm-lock.yaml        # pnpm lock file
├── README.md             # This file
└── tsconfig.json         # TypeScript compiler options
```

## Further Development

_(Add details about potential future enhancements, contribution guidelines, etc.)_
