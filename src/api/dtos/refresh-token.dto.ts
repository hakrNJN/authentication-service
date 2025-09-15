import { z } from 'zod';

/**
 * Zod schema for validating refresh token request payloads.
 */
export const RefreshTokenSchema = z.object({
    refreshToken: z.string({ required_error: 'Refresh token is required' })
        .min(1, 'Refresh token cannot be empty'),
});

/**
 * TypeScript type inferred from the RefreshTokenSchema's body definition.
 * Represents the expected structure of the validated request body for token refresh.
 */
export type RefreshTokenDto = z.infer<typeof RefreshTokenSchema>;

