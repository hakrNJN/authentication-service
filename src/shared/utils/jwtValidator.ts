import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { decode, verify, Algorithm } from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';
import { IConfigService } from '../../application/interfaces/IConfigService';
import { ILogger } from '../../application/interfaces/ILogger';
import { AuthenticationError } from '../../domain';
import { TYPES } from '../constants/types';
import { container } from 'tsyringe';

interface Jwk {
    kid: string;
    alg: string;
    kty: "RSA";
    e: string;
    n: string;
    use: string;
}

interface Jwks {
    keys: Jwk[];
}

let cachedJwks: Jwks | null = null;

export class JwtValidator {
    private readonly userPoolId: string;
    private readonly region: string;
    private readonly logger: ILogger;
    private readonly configService: IConfigService;

    constructor() {
        this.logger = container.resolve<ILogger>(TYPES.Logger);
        this.configService = container.resolve<IConfigService>(TYPES.ConfigService);
        this.userPoolId = this.configService.getOrThrow('COGNITO_USER_POOL_ID');
        this.region = this.configService.getOrThrow('AWS_REGION');
    }

    private async fetchJwks(): Promise<Jwks> {
        if (cachedJwks) {
            return cachedJwks;
        }

        const jwksUrl = `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}/.well-known/jwks.json`;
        try {
            const response = await fetch(jwksUrl);
            if (!response.ok) {
                throw new Error(`Failed to fetch JWKS: ${response.statusText}`);
            }
            const jwks: Jwks = await response.json();
            cachedJwks = jwks;
            return jwks;
        } catch (error: any) {
            this.logger.error(`Error fetching JWKS from ${jwksUrl}: ${error.message}`, error);
            throw new AuthenticationError('Failed to retrieve public keys for token validation.');
        }
    }

    public async validateJwt(token: string): Promise<any> {
        const jwks = await this.fetchJwks();

        const decodedToken = decode(token, { complete: true });

        if (!decodedToken || typeof decodedToken === 'string' || !decodedToken.header.kid) {
            throw new AuthenticationError('Invalid token format or missing KID.');
        }

        const jwk = jwks.keys.find(key => key.kid === decodedToken.header.kid);

        if (!jwk) {
            throw new AuthenticationError('Public key not found for token KID.');
        }

        const pem = jwkToPem(jwk);

        try {
            const verifiedToken = verify(token, pem, {
                algorithms: [jwk.alg as Algorithm], // Ensure algorithm matches
                issuer: `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}`,
                audience: this.configService.getOrThrow('COGNITO_CLIENT_ID'), // Uncommented for audience validation
            });
            return verifiedToken;
        } catch (error: any) {
            this.logger.error(`JWT verification failed: ${error.message}`, error);
            throw new AuthenticationError(`Invalid token: ${error.message}`);
        }
    }
}
