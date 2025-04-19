import { ChallengeNameType } from '@aws-sdk/client-cognito-identity-provider';
import { z } from 'zod';

// Define an enum-like object for allowed ChallengeNameType values in Zod
const AllowedChallengeNames = z.enum([
    ChallengeNameType.SMS_MFA,
    ChallengeNameType.SOFTWARE_TOKEN_MFA,
    ChallengeNameType.DEVICE_PASSWORD_VERIFIER,
    // Add others like MFA_SETUP if needed
]);

/**
 * Zod schema for validating MFA verification request payloads.
 */
export const VerifyMfaSchema = z.object({
    body: z.object({
        username: z.string({ required_error: 'Username is required' })
                     .min(1, 'Username cannot be empty'),

        session: z.string({ required_error: 'Session is required' })
                    .min(20, 'Session seems too short'), // Basic sanity check

        challengeName: AllowedChallengeNames, // Use the Zod enum

        // 'code' can be the MFA code (TOTP/SMS) or a JSON string for Passkey/FIDO2
        code: z.string({ required_error: 'MFA code or assertion response is required' })
                 .min(1, 'MFA code/response cannot be empty'),
    }),
});

/**
 * TypeScript type inferred from the VerifyMfaSchema's body definition.
 */
export type VerifyMfaDto = z.infer<typeof VerifyMfaSchema>['body'];

/**
 * Explicit type alias for ChallengeNameType for clarity in service/controller.
 */
export type MfaChallengeType = z.infer<typeof AllowedChallengeNames>;