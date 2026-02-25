export interface IEventBus {
    /**
     * Publishes a message to a specific topic or exchange.
     * @param topic The name of the topic or routing key
     * @param message The payload to send
     */
    publish<T>(topic: string, message: T): Promise<void>;

    /**
     * Subscribes to a specific topic or queue.
     * @param topic The name of the topic or queue to listen to
     * @param handler The callback function to process incoming messages
     */
    subscribe<T>(topic: string, handler: (message: T) => Promise<void>): Promise<void>;
}
