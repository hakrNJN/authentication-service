import { z } from 'zod';

/**
 * Zod schema for validating forgot password request payloads.
 */
export const ForgotPasswordSchema = z.object({
    body: z.object({
        username: z.string({ required_error: 'Username or email is required' })
                     .min(1, 'Username/email cannot be empty'),
                     // Consider adding .email() if only email is allowed
    }),
});

/**
 * TypeScript type inferred from the ForgotPasswordSchema's body definition.
 */
export type ForgotPasswordDto = z.infer<typeof ForgotPasswordSchema>['body'];

