import { z } from 'zod';

/**
 * Zod schema for validating user signup request payloads.
 */
export const SignUpSchema = z.object({
    body: z.object({
        username: z.string({ required_error: 'Username is required' })
                     .min(3, 'Username must be at least 3 characters long') // Example minimum length
                     .max(100, 'Username cannot exceed 100 characters'),
                     // Depending on Cognito config, username might need to be email:
                     // .email('Username must be a valid email address'),

        password: z.string({ required_error: 'Password is required' })
                     .min(8, 'Password must be at least 8 characters long')
                     // Add regex for complexity if needed, matching Cognito policy
                     // .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
                     //        'Password must contain uppercase, lowercase, number, and special character'),
                     .max(128, 'Password cannot exceed 128 characters'), // Example max length

        attributes: z.object({
            email: z.string({ required_error: 'Email attribute is required' })
                      .email('Invalid email format'),
            name: z.string({ required_error: 'Name attribute is required' })
                     .min(1, 'Name cannot be empty')
                     .max(100, 'Name cannot exceed 100 characters'),
            // Add other required/optional custom attributes based on Cognito setup
            // phone_number: z.string().optional(), // Example optional attribute
        })
        // .passthrough() // REMOVED: Disallow extra attributes to match Record<string, string>
        // Use .strict() if NO extra attributes should be allowed at all, otherwise just removing passthrough works
        // .strict("Unrecognized attributes are not allowed.")
        ,
    }),
});

/**
 * TypeScript type inferred from the SignUpSchema's body definition.
 */
export type SignUpDto = z.infer<typeof SignUpSchema>['body'];

