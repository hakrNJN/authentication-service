import { CodeDeliveryDetailsType } from "@aws-sdk/client-cognito-identity-provider";
import { AuthTokens, SignUpDetails, SignUpResult } from "./IAuthAdapter"; // Import related types

/**
 * Defines the contract for the core authentication application logic.
 * This service orchestrates interactions between the API layer, domain logic (if any),
 * and the infrastructure layer (specifically the IAuthAdapter).
 */
export interface IAuthService {
    /**
     * Handles user login request.
     * @param username - The user's identifier.
     * @param password - The user's password.
     * @returns A promise resolving to authentication tokens upon successful login.
     * @throws {AuthenticationError | ValidationError | BaseError} For login failures.
     */
    login(username: string, password: string): Promise<AuthTokens>;

    /**
     * Handles token refresh request.
     * @param refreshToken - The refresh token.
     * @returns A promise resolving to new authentication tokens.
     * @throws {AuthenticationError} If the refresh token is invalid.
     */
    refresh(refreshToken: string): Promise<AuthTokens>;

    /**
     * Retrieves user information associated with a valid access token.
     * @param accessToken - The user's access token.
     * @returns A promise resolving to the user's details/attributes.
     * @throws {AuthenticationError} If the token is invalid.
     */
    getUserInfo(accessToken: string): Promise<Record<string, any>>;

    /**
     * Handles user signup request.
     * @param details - User signup details (username, password, attributes).
     * @returns A promise resolving to the signup result (userSub, confirmation status).
     * @throws {ValidationError | UsernameExistsException | BaseError} For signup failures.
     */
    signUp(details: SignUpDetails): Promise<SignUpResult>;

    /**
     * Handles confirmation of user signup.
     * @param username - The user's identifier.
     * @param confirmationCode - The confirmation code sent to the user.
     * @returns A promise resolving upon successful confirmation.
     * @throws {AuthenticationError | BaseError} For confirmation failures.
     */
    confirmSignUp(username: string, confirmationCode: string): Promise<void>;

    /**
     * Handles user logout request.
     * @param accessToken - The user's valid access token to invalidate sessions.
     * @returns A promise resolving upon successful logout.
     * @throws {AuthenticationError} If the token is invalid.
     */
    logout(accessToken: string): Promise<void>;

    /**
     * Handles initiating the forgot password flow for a user.
     * @param username - The user's identifier.
     * @returns A promise resolving with code delivery details (or void if not applicable).
     * @throws {ValidationError | NotFoundError | BaseError} For failures.
     */
    initiateForgotPassword(username: string): Promise<CodeDeliveryDetailsType | undefined>;

    /**
     * Handles confirming the forgot password flow and setting a new password.
     * @param username - The user's identifier.
     * @param confirmationCode - The confirmation code.
     * @param newPassword - The new password.
     * @returns A promise resolving upon successful password reset.
     * @throws {ValidationError | AuthenticationError | BaseError} For failures.
     */
    confirmForgotPassword(username: string, confirmationCode: string, newPassword: string): Promise<void>;

    /**
     * Handles a request from an authenticated user to change their password.
     * @param accessToken - The user's valid access token.
     * @param oldPassword - The user's current password.
     * @param newPassword - The desired new password.
     * @returns A promise resolving upon successful password change.
     * @throws {ValidationError | AuthenticationError | BaseError} For failures.
     */
    changePassword(accessToken: string, oldPassword: string, newPassword: string): Promise<void>;

    // Add other methods corresponding to authentication use cases, e.g.:
}

