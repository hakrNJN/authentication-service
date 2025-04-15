import { z } from 'zod';

/**
 * Zod schema for validating refresh token request payloads.
 */
export const RefreshTokenSchema = z.object({
    body: z.object({
        refreshToken: z.string({ required_error: 'Refresh token is required' })
                         .min(1, 'Refresh token cannot be empty'),
    }),
    // Add .query() or .params() if needed
});

/**
 * TypeScript type inferred from the RefreshTokenSchema's body definition.
 * Represents the expected structure of the validated request body for token refresh.
 */
export type RefreshTokenDto = z.infer<typeof RefreshTokenSchema>['body'];

