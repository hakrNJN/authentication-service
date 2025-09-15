import { ChallengeNameType, CodeDeliveryDetailsType } from "@aws-sdk/client-cognito-identity-provider"; // Import necessary type

/**
 * Defines the contract for interacting with an external Identity Provider (IdP)
 * for authentication-related tasks. This abstracts the specific IdP (e.g., Cognito, Auth0).
 */
export interface IAuthAdapter {
    /**
     * Authenticates a user with username and password.
     * @param username - The user's identifier (e.g., email, username).
     * @param password - The user's password.
     * @returns A promise resolving to authentication tokens (e.g., access, refresh, id token).
     * @throws {AuthenticationError | UserNotConfirmedError | PasswordResetRequiredError | MfaRequiredError} If authentication fails or requires action.
     * @throws {BaseError} For other operational errors.
     */
    authenticateUser(username: string, password: string): Promise<AuthTokens>;

    /**
     * Responds to an authentication challenge (e.g., MFA, new password required).
     * @param username - The user's identifier.
     * @param session - The session string received from the initial authentication attempt that resulted in a challenge.
     * @param challengeName - The name of the challenge being responded to.
     * @param responses - A map of challenge responses required by Cognito (e.g., { SMS_MFA_CODE: '123456' }).
     * @returns A promise resolving to authentication tokens upon successful challenge completion.
     * @throws {AuthenticationError} If the challenge response is invalid or the session expires.
     * @throws {BaseError} For other operational errors.
     */
    respondToAuthChallenge(username: string, session: string, challengeName: ChallengeNameType, responses: Record<string, string>): Promise<AuthTokens>;

    /**
     * Refreshes authentication tokens using a refresh token.
     * @param refreshToken - The refresh token provided during initial authentication.
     * @returns A promise resolving to new authentication tokens (typically access and id token).
     * @throws {AuthenticationError} If the refresh token is invalid or expired.
     */
    refreshToken(refreshToken: string): Promise<AuthTokens>;

    /**
     * Initiates an administrative password reset for a user.
     * @param username - The user's identifier.
     * @returns A promise resolving when the reset process is initiated.
     * @throws {NotFoundError} If the user does not exist.
     */
    adminInitiateForgotPassword(username: string): Promise<void>;

    /**
     * Confirms an administrative password reset using a confirmation code.
     * @param username - The user's identifier.
     * @param confirmationCode - The code sent to the user (e.g., via email/SMS).
     * @param newPassword - The new password for the user.
     * @returns A promise resolving when the password has been successfully reset.
     * @throws {AuthenticationError} If the code is invalid or expired.
     * @throws {ValidationError} If the new password doesn't meet policy requirements.
     */
    adminSetPassword(username: string, newPassword: string): Promise<void>;

    /**
     * Retrieves user information based on a valid access token.
     * @param accessToken - The user's access token.
     * @returns A promise resolving to user attributes/details.
     * @throws {AuthenticationError} If the token is invalid or expired.
     */
    getUserFromToken(accessToken: string): Promise<Record<string, any>>;

    /**
     * Registers a new user.
     * @param details - User details including username, password, and attributes (e.g., email, name).
     * @returns A promise resolving to signup result information (e.g., userSub, confirmation status, code delivery details).
     * @throws {ValidationError} If input parameters are invalid (e.g., password policy).
     * @throws {UsernameExistsException} If the username already exists.
     * @throws {BaseError} For other operational errors.
     */
    signUp(details: SignUpDetails): Promise<SignUpResult>;

    /**
     * Confirms user registration using a confirmation code.
     * @param username - The user's identifier.
     * @param confirmationCode - The code sent to the user (e.g., via email/SMS).
     * @returns A promise resolving when the user is successfully confirmed.
     * @throws {AuthenticationError} If the code is invalid/expired or user not found.
     */
    confirmSignUp(username: string, confirmationCode: string): Promise<void>;

    /**
     * Signs the user out globally by invalidating tokens associated with the access token.
     * (e.g., invalidates refresh tokens using Cognito's GlobalSignOut).
     * @param accessToken - A valid access token for the user.
     * @returns A promise resolving when the sign-out process is completed.
     * @throws {AuthenticationError} If the access token is invalid.
     */
    signOut(accessToken: string): Promise<void>;

    /**
     * Initiates the forgot password flow for a user.
     * Typically sends a confirmation code to the user's verified email or phone.
     * @param username - The user's identifier (e.g., email or username).
     * @returns A promise resolving with details about where the code was sent.
     * @throws {NotFoundError} If the user is not found.
     * @throws {BaseError} For other operational errors (e.g., rate limiting, delivery failure).
     */
    initiateForgotPassword(username: string): Promise<CodeDeliveryDetailsType | undefined>;

    

    /**
     * Confirms the forgot password flow using the code and sets a new password.
     * @param username - The user's identifier.
     * @param confirmationCode - The code sent to the user.
     * @param newPassword - The new password to set for the user.
     * @returns A promise resolving when the password has been successfully reset.
     * @throws {AuthenticationError} If the code is invalid/expired or user not found.
     * @throws {ValidationError} If the new password doesn't meet policy requirements.
     * @throws {BaseError} For other operational errors (e.g., rate limiting).
     */
    confirmForgotPassword(username: string, confirmationCode: string, newPassword: string): Promise<void>;

    /**
     * Allows an authenticated user to change their own password.
     * @param accessToken - A valid access token for the currently logged-in user.
     * @param previousPassword - The user's current password.
     * @param proposedPassword - The new password the user wants to set.
     * @returns A promise resolving when the password change is successful.
     * @throws {AuthenticationError} If the access token is invalid or the previous password doesn't match.
     * @throws {ValidationError} If the proposed password doesn't meet policy requirements.
     * @throws {BaseError} For other operational errors.
     */
    changePassword(accessToken: string, previousPassword: string, proposedPassword: string): Promise<void>;

  // TODO: Add adminAddUserToGroup for RBAC step later
    // adminAddUserToGroup(username: string, groupName: string): Promise<void>;

    // Add other methods as needed
}

/**
 * Represents the set of tokens typically returned upon successful authentication or refresh.
 */
export interface AuthTokens {
    accessToken: string;
    refreshToken?: string;
    idToken?: string;
    expiresIn: number;
    tokenType: string;
}

/**
 * Represents the details required for user signup.
 */
export interface SignUpDetails {
    username: string; // Often email, but depends on Cognito config
    password: string;
    attributes: Record<string, string>; // e.g., { email: 'test@example.com', name: 'Test User' }
    // Add clientMetadata if needed for triggers
}

/**
 * Represents the result of a successful signup operation.
 */
export interface SignUpResult {
    userSub: string; // The unique identifier for the user in Cognito
    userConfirmed: boolean;
    codeDeliveryDetails?: CodeDeliveryDetailsType; // Details on where confirmation code was sent
}
