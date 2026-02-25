import * as amqp from 'amqplib';
import { Channel, Connection } from 'amqplib';
import { injectable, inject } from 'tsyringe';
import { IConfigService } from '../../application/interfaces/IConfigService';
import { IEventBus } from '../../application/interfaces/IEventBus';
import { ILogger } from '../../application/interfaces/ILogger';
import { TYPES } from '../../shared/constants/types';

@injectable()
export class RabbitMqEventBus implements IEventBus {
    private connection: any = null;
    private channel: Channel | null = null;
    private url: string;
    private exchange: string;

    constructor(
        @inject(TYPES.ConfigService) private configService: IConfigService,
        @inject(TYPES.Logger) private logger: ILogger
    ) {
        this.url = this.configService.get('RABBITMQ_URL', 'amqp://localhost') as string;
        this.exchange = this.configService.get('RABBITMQ_EXCHANGE', 'pbac-events-exchange') as string;
    }

    private async connect(): Promise<Channel> {
        if (this.channel) return this.channel;

        try {
            this.connection = await amqp.connect(this.url);
            this.channel = await this.connection.createChannel();

            if (!this.channel) {
                throw new Error('Failed to create RabbitMQ channel');
            }

            await this.channel.assertExchange(this.exchange, 'topic', { durable: true });

            this.logger.info(`[RabbitMqEventBus] Connected to RabbitMQ at ${this.url}`);
            return this.channel;
        } catch (error) {
            this.logger.error(`[RabbitMqEventBus] Failed to connect to RabbitMQ`, error);
            throw error;
        }
    }

    async publish<T>(topic: string, message: T): Promise<void> {
        try {
            const channel = await this.connect();
            const payload = Buffer.from(JSON.stringify(message));

            const published = channel.publish(this.exchange, topic, payload, { persistent: true });

            if (published) {
                this.logger.debug(`[RabbitMqEventBus] Published message to topic ${topic}`);
            } else {
                this.logger.warn(`[RabbitMqEventBus] Publish buffer full for topic ${topic}`);
            }
        } catch (error) {
            this.logger.error(`[RabbitMqEventBus] Failed to publish message`, error);
            throw error;
        }
    }

    async subscribe<T>(topic: string, handler: (message: T) => Promise<void>): Promise<void> {
        try {
            const channel = await this.connect();

            // Generate a queue based on the topic and service name
            const queueName = `authz-service-${topic}-queue`;

            // Assert queue and bind it to the exchange with the routing key (topic)
            await channel.assertQueue(queueName, { durable: true });
            await channel.bindQueue(queueName, this.exchange, topic);

            this.logger.info(`[RabbitMqEventBus] Subscribed to RabbitMQ topic: ${topic}`);

            await channel.consume(queueName, async (msg) => {
                if (msg !== null) {
                    try {
                        const parsedMessage = JSON.parse(msg.content.toString()) as T;
                        await handler(parsedMessage);
                        channel.ack(msg); // Acknowledge successful processing
                    } catch (handlerErr) {
                        this.logger.error(`[RabbitMqEventBus] Error handling message`, handlerErr);
                        // Depending on the use case, you might `nack` or dead-letter the message
                        channel.nack(msg, false, false);
                    }
                }
            });
        } catch (error) {
            this.logger.error(`[RabbitMqEventBus] Failed to subscribe to topic ${topic}`, error);
            throw error;
        }
    }
}
