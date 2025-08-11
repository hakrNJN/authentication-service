# Authentication Service Summary

## Overview

This microservice handles user authentication and authorization. It provides endpoints for user registration, login, password management, and token management. It is designed to be used as a standalone service that can be integrated into a larger microservices architecture.

## Tech Stack

*   **Node.js**: Runtime environment
*   **Express.js**: Web framework
*   **TypeScript**: Programming language
*   **AWS Cognito**: Authentication provider
*   **Jest**: Testing framework
*   **Winston**: Logger
*   **Inversify**: Dependency injection
*   **Zod**: Schema validation

## Project Structure

The project is structured using a clean architecture approach, with a clear separation of concerns between the different layers of the application.

*   `src/`: Source code
    *   `api/`: API layer (controllers, routes, middlewares, DTOs)
    *   `application/`: Application layer (services, use cases, interfaces)
    *   `domain/`: Domain layer (entities, exceptions, value-objects)
    *   `infrastructure/`: Infrastructure layer (adapters, config, persistence)
    *   `shared/`: Shared code (constants, errors, types, utils)
*   `tests/`: Tests

## Available Routes

### Authentication Routes

*   `POST /auth/signup`: Register a new user.
*   `POST /auth/confirm-signup`: Confirm a new user's registration.
*   `POST /auth/login`: Log in a user.
*   `POST /auth/verify-mfa`: Verify a user's MFA code.
*   `POST /auth/refresh-token`: Refresh a user's authentication token.
*   `POST /auth/forgot-password`: Initiate the password reset process.
*   `POST /auth/reset-password`: Reset a user's password.
*   `POST /auth/change-password`: Change a user's password.
*   `GET /auth/me`: Get the current user's information.
*   `POST /auth/logout`: Log out a user.

### System Routes

*   `GET /system/health`: Health check endpoint.
*   `GET /system/server-info`: Get server information.

## Authentication Flow

1.  The user registers for an account using the `/auth/signup` endpoint.
2.  The user confirms their registration using the `/auth/confirm-signup` endpoint.
3.  The user logs in using the `/auth/login` endpoint.
4.  If the user has MFA enabled, they will be prompted to enter their MFA code using the `/auth/verify-mfa` endpoint.
5.  Upon successful login, the user will receive an access token and a refresh token.
6.  The access token is used to authenticate the user for protected routes.
7.  The refresh token is used to obtain a new access token when the old one expires.

## How to Run

1.  Install dependencies: `pnpm install`
2.  Run the service: `pnpm start`
3.  Run tests: `pnpm test`
