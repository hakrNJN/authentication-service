import { z } from 'zod';

/**
 * Zod schema for validating forgot password request payloads.
 */
export const ForgotPasswordSchema = z.object({
    username: z.string({ required_error: 'Username or email is required' })
        .min(1, 'Username/email cannot be empty')
        .max(128, 'Username is too long')
        .refine(
            (value) => /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(value),
            'Invalid email format'
        ),
});

/**
 * TypeScript type inferred from the ForgotPasswordSchema's body definition.
 */
export type ForgotPasswordDto = z.infer<typeof ForgotPasswordSchema>;

