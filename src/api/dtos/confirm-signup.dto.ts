import { z } from 'zod';

/**
 * Zod schema for validating signup confirmation request payloads.
 */
export const ConfirmSignUpSchema = z.object({
    username: z.string({ required_error: 'Username is required' })
        .min(1, 'Username cannot be empty'),

    confirmationCode: z.string({ required_error: 'Confirmation code is required' })
        .min(6, 'Confirmation code must be exactly 6 digits')
        .max(6, 'Confirmation code must be exactly 6 digits')
        .regex(/^\d{6}$/, 'Confirmation code must be numeric'),
});

/**
 * TypeScript type inferred from the ConfirmSignUpSchema's body definition.
 */
export type ConfirmSignUpDto = z.infer<typeof ConfirmSignUpSchema>;

