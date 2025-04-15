import { z } from 'zod';

/**
 * Zod schema for validating signup confirmation request payloads.
 */
export const ConfirmSignUpSchema = z.object({
    body: z.object({
        username: z.string({ required_error: 'Username is required' })
                     .min(1, 'Username cannot be empty'),
                     // Add .email() if username must be an email

        confirmationCode: z.string({ required_error: 'Confirmation code is required' })
                             .min(1, 'Confirmation code cannot be empty')
                             .max(10, 'Confirmation code seems too long'), // Adjust max length as needed
    }),
});

/**
 * TypeScript type inferred from the ConfirmSignUpSchema's body definition.
 */
export type ConfirmSignUpDto = z.infer<typeof ConfirmSignUpSchema>['body'];

