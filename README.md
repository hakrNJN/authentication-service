# Authentication Service

This service is responsible for handling all user authentication processes, including registration, login, password management, and token management within the PBAC system.

## Table of Contents
- [Folder Structure](#folder-structure)
- [Tech Stack](#tech-stack)
- [Design Patterns and Principles](#design-patterns-and-principles)
- [Purpose and Key Functionalities](#purpose-and-key-functionalities)
- [API Endpoints](#api-endpoints)
- [Dependencies](#dependencies)
- [Environment Variables](#environment-variables)
- [Local Setup Instructions](#local-setup-instructions)

## Folder Structure
```
authentication-service/
├── src/
│   ├── api/                  # API layer (controllers, DTOs, middlewares, routes)
│   │   ├── controllers/      # Request handling logic
│   │   ├── dtos/             # Data Transfer Objects for request/response validation
│   │   ├── middlewares/      # Express middleware (e.g., authentication, validation)
│   │   └── routes/           # Defines API endpoints and maps to controllers
│   ├── application/          # Application layer (orchestrates domain logic, use cases)
│   ├── domain/               # Domain layer (core business logic, entities, value objects)
│   ├── infrastructure/       # Infrastructure layer (database interactions, external services, logging)
│   ├── shared/               # Shared utilities, types, constants
│   ├── app.ts                # Express application setup
│   ├── container.ts          # Dependency Injection container setup (tsyringe)
│   └── main.ts               # Application entry point
├── tests/                    # Unit, Integration, and E2E tests
├── .env.example              # Example environment variables
├── Dockerfile                # Docker build instructions
├── package.json              # Project dependencies and scripts
├── pnpm-lock.yaml            # pnpm lock file
└── README.md                 # This documentation
```

## Tech Stack
- **Language:** TypeScript
- **Runtime:** Node.js
- **Web Framework:** Express.js
- **Package Manager:** pnpm
- **Authentication:** JSON Web Tokens (JWT), JWK to PEM conversion, AWS Cognito (via AWS SDK)
- **Caching/Session Management:** Redis (via `ioredis`) for token blacklisting
- **Dependency Injection:** tsyringe
- **Validation:** Zod
- **Logging:** Winston (with CloudWatch and Elasticsearch transports)
- **Observability:** OpenTelemetry (for tracing and metrics), Prometheus (via `prom-client`)
- **Resilience:** Opossum (Circuit Breaker)

## Design Patterns and Principles
- **Layered Architecture:** The service is structured into distinct layers (API, Application, Domain, Infrastructure) to promote separation of concerns and maintainability.
- **Dependency Injection:** Utilizes `tsyringe` to manage dependencies, making the codebase more modular and testable.
- **Circuit Breaker:** Implements the Circuit Breaker pattern using `opossum` to prevent cascading failures and improve system resilience.
- **Observability:** Designed with observability in mind, integrating OpenTelemetry for distributed tracing and `prom-client` for Prometheus metrics.
- **Token Blacklisting:** Employs Redis to manage a blacklist of invalidated tokens, enhancing security.

## Purpose and Key Functionalities
**Purpose:** To provide secure and efficient user authentication for the PBAC system.

**Key Functionalities:**
- **User Registration & Confirmation:** Allows new users to sign up and confirm their accounts.
- **User Login:** Authenticates users and issues access tokens.
- **Multi-Factor Authentication (MFA):** Supports MFA verification during login.
- **Token Management:** Handles access token refreshing and invalidation (logout).
- **Password Management:** Provides functionalities for forgotten, resetting, and changing passwords.
- **User Information Retrieval:** Allows authenticated users to retrieve their profile information.
- **System Monitoring:** Provides health check, server information, and Prometheus metrics endpoints for operational visibility.

## API Endpoints
All endpoints are typically prefixed with `/api/auth`.

- `POST /signup`: Registers a new user.
- `POST /confirm-signup`: Confirms a user's registration.
- `POST /login`: Authenticates a user and returns tokens.
- `POST /verify-mfa`: Verifies MFA code during login.
- `POST /refresh-token`: Refreshes an expired access token.
- `POST /forgot-password`: Initiates the password reset process.
- `POST /reset-password`: Resets a user's password.
- `POST /change-password`: Changes the authenticated user's password.
- `GET /me`: Retrieves information about the authenticated user.
- `POST /logout`: Invalidates the authenticated user's session/token.

**System Endpoints (typically not requiring authentication):**
- `GET /health`: Returns the health status of the service.
- `GET /server-info`: Provides general information about the server and service.
- `GET /metrics`: Exposes Prometheus-compatible metrics for monitoring.

## Dependencies
Key dependencies include:
- `@aws-sdk/client-cognito-identity-provider`: For interacting with AWS Cognito.
- `express`: Web framework.
- `ioredis`: Redis client for token blacklisting.
- `jsonwebtoken`, `jwk-to-pem`: For JWT handling.
- `tsyringe`: Dependency injection container.
- `zod`: For data validation.
- `winston`: Logging library.
- `@opentelemetry/*`: For distributed tracing and metrics.
- `prom-client`: For Prometheus metrics.
- `opossum`: For circuit breaker implementation.
- `dotenv`: For environment variable management.

## Environment Variables
Configuration is managed via environment variables. A `.env.example` file is provided as a template.

| Variable                  | Description                                          | Example Value       |
|---------------------------|------------------------------------------------------|---------------------|
| `NODE_ENV`                | Node.js environment (e.g., development, production). | `development`       |
| `PORT`                    | Port on which the service will listen.               | `3000`              |
| `LOG_LEVEL`               | Minimum logging level (e.g., info, debug, error).    | `debug`             |
| `AWS_REGION`              | AWS region for services like Cognito.                | `asia-south-1`      |
| `COGNITO_USER_POOL_ID`    | AWS Cognito User Pool ID.                            | `your-user-pool-id` |
| `COGNITO_CLIENT_ID`       | AWS Cognito App Client ID.                           | `your-client-id`    |
| `USE_REDIS_BLACKLIST`     | Whether to use Redis for token blacklisting.         | `true`              |
| `REDIS_URL`               | URL for the Redis server.                            | `redis://localhost:6379` |

## Local Setup Instructions

To set up and run the Authentication Service locally, follow these steps:

1.  **Prerequisites:**
    *   Node.js (v20 or higher recommended)
    *   pnpm (v8 or higher recommended)
    *   Docker and Docker Compose

2.  **Clone the Repository:**
    ```bash
    git clone <repository-url>
    cd authentication-service
    ```

3.  **Install Dependencies:**
    ```bash
    pnpm install
    ```

4.  **Environment Configuration:**
    Create a `.env` file in the root of the `authentication-service` directory by copying `.env.example` and filling in the appropriate values.
    ```bash
    cp .env.example .env
    # Edit .env with your specific AWS credentials and Cognito details
    ```

5.  **Run with Docker Compose (Recommended for local development):**
    The `docker-compose.yml` in the project root orchestrates all services, including Redis.
    Navigate to the project root (`E:\NodeJS\PBAC_Auth`) and run:
    ```bash
    docker compose up -d redis
    ```
    Then, from the `authentication-service` directory, start the service in development mode:
    ```bash
    pnpm run dev
    ```

6.  **Build and Run (Production-like):**
    ```bash
    pnpm run build
    pnpm run start
    ```

7.  **Running Tests:**
    ```bash
    pnpm test
    ```