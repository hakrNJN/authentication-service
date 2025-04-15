/**
 * Defines the contract for logging services throughout the application.
 * This allows swapping logging implementations (e.g., Winston, Pino) without changing application code.
 */
export interface ILogger {
    /**
     * Logs informational messages.
     * @param message - The primary log message.
     * @param meta - Optional additional metadata (e.g., objects, context).
     */
    info(message: string, meta?: Record<string, any>): void;

    /**
     * Logs warning messages.
     * @param message - The primary log message.
     * @param meta - Optional additional metadata.
     */
    warn(message: string, meta?: Record<string, any>): void;

    /**
     * Logs error messages. Typically used for caught errors or exceptional conditions.
     * @param message - The primary log message.
     * @param error - Optional Error object or other relevant data.
     * @param meta - Optional additional metadata.
     */
    error(message: string, error?: Error | any, meta?: Record<string, any>): void;

    /**
     * Logs debug messages, usually for detailed troubleshooting information.
     * Often disabled in production environments.
     * @param message - The primary log message.
     * @param meta - Optional additional metadata.
     */
    debug(message: string, meta?: Record<string, any>): void;

    // Add other levels like 'http', 'verbose', 'silly' if needed, matching your chosen logger's levels.
}

