import { z } from 'zod';

/**
 * Zod schema for validating login request payloads.
 */
export const LoginSchema = z.object({
    body: z.object({
        username: z.string({ required_error: 'Username is required' })
                     .min(1, 'Username cannot be empty')
                     .max(100, 'Username cannot exceed 100 characters'),
                     // Add .email() if username must be an email address:
                     // .email('Invalid email format'),

        password: z.string({ required_error: 'Password is required' })
                     .min(8, 'Password must be at least 8 characters long'),
                     // Add more password complexity rules if needed via .regex()
    }),
    // Add .query() or .params() if needed for validation
});

/**
 * TypeScript type inferred from the LoginSchema's body definition.
 * Represents the expected structure of the validated request body for login.
 */
export type LoginDto = z.infer<typeof LoginSchema>['body'];

