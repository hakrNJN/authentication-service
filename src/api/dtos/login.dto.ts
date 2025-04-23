import { z } from 'zod';

/**
 * Zod schema for validating login request payloads.
 */
export const LoginSchema = z.object({
    username: z.string({ required_error: 'Username is required' })
                 .min(1, 'Username cannot be empty')
                 .max(100, 'Username cannot exceed 100 characters'),
                 // Add .email() if username must be an email address:
                 // .email('Invalid email format'),

    password: z.string({ required_error: 'Password is required' })
                 .min(1, 'Password cannot be empty'),
                 // Password complexity is enforced by the auth service, not the schema
});

/**
 * TypeScript type inferred from the LoginSchema definition.
 * Represents the expected structure of the validated request payload for login.
 */
export type LoginDto = z.infer<typeof LoginSchema>;

