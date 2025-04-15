import { z } from 'zod';

/**
 * Zod schema for validating change password request payloads (for logged-in users).
 */
export const ChangePasswordSchema = z.object({
    body: z.object({
        oldPassword: z.string({ required_error: 'Current password is required' })
                        .min(1, 'Current password cannot be empty'), // Min length might be higher based on policy

        newPassword: z.string({ required_error: 'New password is required' })
                        .min(8, 'New password must be at least 8 characters long')
                        .max(128, 'New password cannot exceed 128 characters'),
                        // Add regex for complexity if needed
    }),
    // We don't validate accessToken here, that's the job of the auth guard middleware
});

/**
 * TypeScript type inferred from the ChangePasswordSchema's body definition.
 */
export type ChangePasswordDto = z.infer<typeof ChangePasswordSchema>['body'];

