/**
 * Defines the contract for generating and verifying custom tokens (e.g., JWTs)
 * within the application, potentially separate from the primary IdP tokens.
 * This might be used for session management or specific internal authorization.
 */
export interface ITokenService {
    /**
     * Generates a new token based on the provided payload.
     * @param payload - The data to include in the token payload (e.g., userId, roles).
     * @param expiresIn - Optional expiration time (e.g., '1h', '7d'). Uses a default if not provided.
     * @returns A promise resolving to the generated token string.
     */
    generateToken(payload: Record<string, any>, expiresIn?: string): Promise<string>;

    /**
     * Verifies a token's validity and signature, returning its payload.
     * @param token - The token string to verify.
     * @returns A promise resolving to the decoded token payload if valid.
     * @throws {AuthenticationError} If the token is invalid, expired, or malformed.
     */
    verifyToken<T = Record<string, any>>(token: string): Promise<T>;

    // Add other methods if needed, e.g., decodeToken (without verification)
    // decodeToken<T = Record<string, any>>(token: string): Promise<T | null>;
}

