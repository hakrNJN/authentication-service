import { z } from 'zod';

/**
 * Zod schema for validating forgot password request payloads.
 */
export const ForgotPasswordSchema = z.object({
    username: z.string({ required_error: 'Username or email is required' })
        .min(1, 'Username/email cannot be empty')
        .max(128, 'Username is too long')
        .regex(/^[a-zA-Z0-9_.\-@+]+$/, 'Username can only contain letters, numbers, underscores, hyphens, periods, @ and +'),
});

/**
 * TypeScript type inferred from the ForgotPasswordSchema's body definition.
 */
export type ForgotPasswordDto = z.infer<typeof ForgotPasswordSchema>;

