/**
 * Defines the contract for accessing application configuration values.
 * This allows different configuration sources (env vars, files) to be used interchangeably.
 */
export interface IConfigService {
    /**
     * Retrieves a configuration value as a string.
     * @param key - The configuration key.
     * @param defaultValue - Optional default value if the key is not found.
     * @returns The configuration value as a string, or the default value, or undefined.
     */
    get<T = string>(key: string, defaultValue?: T): T | undefined;

    /**
     * Retrieves a configuration value, ensuring it's a number.
     * @param key - The configuration key.
     * @param defaultValue - Optional default value if the key is not found or not a valid number.
     * @returns The configuration value as a number, or the default value, or undefined.
     * @throws Error if the value cannot be parsed as a number and no default is provided.
     */
    getNumber(key: string, defaultValue?: number): number | undefined;

    /**
     * Retrieves a configuration value, ensuring it's a boolean.
     * Parses 'true', '1' as true, and 'false', '0' as false (case-insensitive).
     * @param key - The configuration key.
     * @param defaultValue - Optional default value if the key is not found or not a valid boolean representation.
     * @returns The configuration value as a boolean, or the default value, or undefined.
     * @throws Error if the value cannot be parsed as a boolean and no default is provided.
     */
    getBoolean(key: string, defaultValue?: boolean): boolean | undefined;

    /**
     * Retrieves all configuration values loaded by the service.
     * Use with caution, may expose sensitive information if logged directly.
     * @returns An object containing all configuration key-value pairs.
     */
    getAllConfig(): Record<string, any>;

     /**
     * Checks if a configuration key exists.
     * @param key - The configuration key.
     * @returns True if the key exists, false otherwise.
     */
    has(key: string): boolean;

    getOrThrow<T>(key: string): T;
    
//  /**
//      * Ensures that required configuration keys are present.
//      * Throws an error if any required key is missing.
//      * Should be called during bootstrap after loading config.
//      * @param requiredKeys - An array of keys that must be defined.
//      */
//     ensureRequiredKeys(keys: string[]): void;
}

