import { injectable } from 'tsyringe';
import { IConfigService } from '../../application/interfaces/IConfigService';
// Removed dotenv and path imports

@injectable()
export class EnvironmentConfigService implements IConfigService {
    private readonly config: Record<string, string | undefined>;
    // Define required keys directly in the class
    private readonly requiredKeys: string[] = [
        'NODE_ENV',
        'PORT',
        'LOG_LEVEL',
        'AWS_REGION',
        'COGNITO_USER_POOL_ID',
        'COGNITO_CLIENT_ID'
        // Add other *essential* keys here
    ];

    constructor() {
        // --- Rely on process.env populated by Node's --env-file flag ---
        // No need to call dotenv.config() here.
        console.info(`[ConfigService] Reading configuration from process.env (expected to be populated by --env-file)`);

        // Store process.env
        this.config = process.env;
        console.debug('[ConfigService] Configuration loaded from environment variables.');

        // --- Ensure required keys are present right after loading ---
        const missingKeys = this.requiredKeys.filter(key => !this.has(key));
        if (missingKeys.length > 0) {
            const errorMsg = `[ConfigService] Missing required environment variables: ${missingKeys.join(', ')}`;
            console.error(errorMsg);
            // Throw error to prevent application startup with invalid config
            throw new Error(errorMsg);
        }
        console.info('[ConfigService] Required configuration keys verified.');
        // --- End required key check ---
    }

    get<T = string>(key: string, defaultValue?: T): T | undefined {
        const value = this.config[key];
        if (value === undefined) {
            return defaultValue;
        }
        return value as unknown as T;
    }

    getNumber(key: string, defaultValue?: number): number | undefined {
        const value = this.config[key];
        if (value === undefined) {
            return defaultValue;
        }

        const num = parseFloat(value);
        if (isNaN(num)) {
             if (defaultValue !== undefined) {
                 return defaultValue;
            }
            throw new Error(`Configuration error: Environment variable "${key}" is not a valid number ("${value}").`);
        }
        return num;
    }

    getBoolean(key: string, defaultValue?: boolean): boolean | undefined {
        const value = this.config[key]?.toLowerCase();
         if (value === undefined) {
            return defaultValue;
        }

        if (value === 'true' || value === '1') {
            return true;
        }
        if (value === 'false' || value === '0') {
            return false;
        }

        if (defaultValue !== undefined) {
            return defaultValue;
        }
        throw new Error(`Configuration error: Environment variable "${key}" is not a valid boolean ("${value}"). Expected 'true', 'false', '1', or '0'.`);
    }

    getAllConfig(): Record<string, any> {
        return { ...this.config };
    }

     has(key: string): boolean {
        return this.config[key] !== undefined;
    }
}
