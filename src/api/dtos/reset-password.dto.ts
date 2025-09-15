import { z } from 'zod';

/**
 * Zod schema for validating reset password request payloads.
 */
export const ResetPasswordSchema = z.object({
        username: z.string({ required_error: 'Username or email is required' })
                     .min(1, 'Username/email cannot be empty')
                     .email('Invalid email format'), // Assuming username is email for reset

        confirmationCode: z.string({ required_error: 'Confirmation code is required' })
                             .length(6, 'Confirmation code must be exactly 6 digits')
                             .regex(/^\d{6}$/, 'Confirmation code must be numeric'), // Enforce 6-digit numeric

        newPassword: z.string({ required_error: 'New password is required' })
                        .min(8, 'Password must be at least 8 characters long')
                        .max(128, 'Password cannot exceed 128 characters')
                        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
                            'Password must contain uppercase, lowercase, number, and special character'), // Enforce complexity
    
});

/**
 * TypeScript type inferred from the ResetPasswordSchema's body definition.
 */
export type ResetPasswordDto = z.infer<typeof ResetPasswordSchema>;

