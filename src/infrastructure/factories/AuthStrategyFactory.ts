import { inject, injectable } from 'tsyringe';
import { IAuthStrategy } from '../../application/interfaces/IAuthStrategy';
import { IConfigService } from '../../application/interfaces/IConfigService';
import { TYPES } from '../../shared/constants/types';
import { CognitoAuthStrategy } from '../adapters/cognito/CognitoAuthStrategy';
import { Auth0Strategy } from '../adapters/auth0/Auth0Strategy';
import { FirebaseStrategy } from '../adapters/firebase/FirebaseStrategy';
import { OktaStrategy } from '../adapters/okta/OktaStrategy';
import { AuthProvider } from '../../shared/constants/AuthProvider';

@injectable()
export class AuthStrategyFactory {
    constructor(
        @inject(TYPES.ConfigService) private configService: IConfigService,
        @inject(CognitoAuthStrategy) private cognitoStrategy: CognitoAuthStrategy,
        @inject(Auth0Strategy) private auth0Strategy: Auth0Strategy,
        @inject(FirebaseStrategy) private firebaseStrategy: FirebaseStrategy,
        @inject(OktaStrategy) private oktaStrategy: OktaStrategy,
    ) { }

    public getStrategy(): IAuthStrategy {
        const providerRaw = this.configService.get<string>('AUTH_PROVIDER') || 'COGNITO';
        const provider = providerRaw.toUpperCase() as AuthProvider;

        switch (provider) {
            case AuthProvider.COGNITO:
                return this.cognitoStrategy;
            case AuthProvider.AUTH0:
                return this.auth0Strategy;
            case AuthProvider.FIREBASE:
                return this.firebaseStrategy;
            case AuthProvider.OKTA:
                return this.oktaStrategy;
            default:
                throw new Error(`Unsupported AUTH_PROVIDER: ${providerRaw}`);
        }
    }
}
