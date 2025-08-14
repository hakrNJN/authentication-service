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
        'COGNITO_CLIENT_ID',
        'SHARED_SECRET', // Added for shared secret authentication
        'REDIS_URL', // Added for Redis blacklist
        'USE_REDIS_BLACKLIST' // Added for Redis blacklist toggle
        // Add other *essential* keys here
    ];

    // Define patterns for keys considered sensitive and should be filtered
    private readonly sensitiveKeyPatterns: RegExp[] = [
        /password/i,
        /secret/i,
        /(api|private)_?key/i, // Be careful, might match legitimate non-secret keys like 'PRIMARY_KEY'
        /token/i,
        // Add more specific patterns as needed
    ];

    constructor() {
        // TODO: Integrate with a dedicated secret management solution (e.g., AWS Secrets Manager, HashiCorp Vault).
        // This would involve fetching secrets at startup and populating `this.config` with them.
        // Example:
        // const fetchedSecrets = await getSecretsFromAwsSecretsManager();
        // this.config = { ...process.env, ...fetchedSecrets };

        // --- Rely on process.env populated by Node's --env-file flag ---
        console.info(`[ConfigService] Reading configuration from process.env (expected to be populated by --env-file)`);
        this.config = process.env;
        console.debug('[ConfigService] Configuration loaded from environment variables.');
        const missingKeys = this.requiredKeys.filter(key => !this.has(key) || this.config[key] === '');
        if (missingKeys.length > 0) {
            const errorMsg = `[ConfigService] Missing or empty required environment variables: ${missingKeys.join(', ')}`;
            console.error(errorMsg);
            throw new Error(errorMsg);
        }
        console.info('[ConfigService] Required configuration keys verified.');
        // --- End required key check ---
    }

    get<T = string>(key: string, defaultValue?: T): T | undefined {
        const value = this.config[key];
        // Return default if value is undefined OR an empty string
        if (value === undefined || value === '') {
            return defaultValue;
        }
        return value as unknown as T;
    }

    getNumber(key: string, defaultValue?: number): number | undefined {
        const value = this.config[key];
        // Use default if value is undefined or empty string
        if (value === undefined || value === '') {
            return defaultValue;
        }

        const num = parseFloat(value);
        if (isNaN(num)) {
            // If parsing fails, return default if provided
            if (defaultValue !== undefined) {
                console.warn(`[ConfigService] Value for key "${key}" ("${value}") is not a valid number. Using default value: ${defaultValue}`);
                return defaultValue;
            }
            // Otherwise, throw an error as it's invalid config without a fallback
            throw new Error(`Configuration error: Environment variable "${key}" is not a valid number ("${value}").`);
        }
        return num;
    }

    getBoolean(key: string, defaultValue?: boolean): boolean | undefined {
        const value = this.config[key]?.toLowerCase();
        // Use default if value is undefined or empty string
        if (value === undefined || value === '') {
            return defaultValue;
        }

        if (value === 'true' || value === '1') {
            return true;
        }
        if (value === 'false' || value === '0') {
            return false;
        }

        // If parsing fails, return default if provided
        if (defaultValue !== undefined) {
            console.warn(`[ConfigService] Value for key "${key}" ("${this.config[key]}") is not a valid boolean. Using default value: ${defaultValue}`);
            return defaultValue;
        }
        // Otherwise, throw an error
        throw new Error(`Configuration error: Environment variable "${key}" is not a valid boolean ("${this.config[key]}"). Expected 'true', 'false', '1', or '0'.`);
    }

    getAllConfig(): Record<string, any> {
        const filteredConfig: Record<string, any> = {};
        for (const key in this.config) {
            // Check if the key matches any sensitive pattern
            const isSensitive = this.sensitiveKeyPatterns.some(pattern => pattern.test(key));
            if (!isSensitive) {
                filteredConfig[key] = this.config[key];
            } else {
                // Optionally include the key but mask the value
                filteredConfig[key] = '********'; // Mask sensitive values
            }
        }
        // Ensure required keys are present even if sensitive (they might be needed for context)
        this.requiredKeys.forEach(reqKey => {
            if (this.config.hasOwnProperty(reqKey) && !filteredConfig.hasOwnProperty(reqKey)) {
                if (this.sensitiveKeyPatterns.some(pattern => pattern.test(reqKey))) {
                    filteredConfig[reqKey] = '********'; // Ensure required sensitive keys are present but masked
                } else {
                    // This case shouldn't happen often if requiredKeys are not sensitive
                    // Or if the required key didn't match a sensitive pattern anyway
                    filteredConfig[reqKey] = this.config[reqKey];
                }
            }
        });
        return filteredConfig;
    }


    has(key: string): boolean {
        // Checks for the existence of the key, regardless of value (even empty string)
        return this.config[key] !== undefined;
    }

    getOrThrow<T>(key: string): T {
        const value = this.get<T>(key);
        if (value === undefined) {
            throw new Error(`Missing required configuration key: ${key}`);
        }
        return value;
    }

    // Reload logic might need adjustment depending on how --env-file interacts
    // with runtime changes. For simplicity, keeping it as is.
    reloadConfig(): void {
        // Re-read process.env and update config
        // Note: process.env is always live, but this allows explicit reloads if env changes at runtime
        // This might not pick up changes from --env-file if it's only read at startup.
        console.warn("[ConfigService] Reloading config from current process.env. This might not reflect changes from the original --env-file if it hasn't been re-sourced.");
        Object.assign(this.config, process.env);

        // Optionally, re-validate required keys
        const missingKeys = this.requiredKeys.filter(key => !this.has(key) || this.config[key] === '');
        if (missingKeys.length > 0) {
            const errorMsg = `[ConfigService] Missing or empty required environment variables after reload: ${missingKeys.join(', ')}`;
            console.error(errorMsg);
            throw new Error(errorMsg);
        }
        console.info('[ConfigService] Configuration reloaded and required keys verified.');
    }
}