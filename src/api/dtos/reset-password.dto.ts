import { z } from 'zod';

/**
 * Zod schema for validating reset password request payloads.
 */
export const ResetPasswordSchema = z.object({
    body: z.object({
        username: z.string({ required_error: 'Username or email is required' })
                     .min(1, 'Username/email cannot be empty'),
                     // Consider adding .email()

        confirmationCode: z.string({ required_error: 'Confirmation code is required' })
                             .min(1, 'Confirmation code cannot be empty'),

        newPassword: z.string({ required_error: 'New password is required' })
                        .min(8, 'Password must be at least 8 characters long')
                        .max(128, 'Password cannot exceed 128 characters'),
                        // Add regex for complexity if needed
    }),
});

/**
 * TypeScript type inferred from the ResetPasswordSchema's body definition.
 */
export type ResetPasswordDto = z.infer<typeof ResetPasswordSchema>['body'];

