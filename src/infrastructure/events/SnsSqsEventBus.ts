import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from '@aws-sdk/client-sqs';
import { injectable, inject } from 'tsyringe';
import { IConfigService } from '../../application/interfaces/IConfigService';
import { IEventBus } from '../../application/interfaces/IEventBus';
import { ILogger } from '../../application/interfaces/ILogger';
import { TYPES } from '../../shared/constants/types';

@injectable()
export class SnsSqsEventBus implements IEventBus {
    private snsClient: SNSClient;
    private sqsClient: SQSClient;
    private topicArn: string;
    private queueUrl: string;

    constructor(
        @inject(TYPES.ConfigService) private configService: IConfigService,
        @inject(TYPES.Logger) private logger: ILogger
    ) {
        const region = this.configService.get('AWS_REGION', 'us-east-1');
        this.snsClient = new SNSClient({ region });
        this.sqsClient = new SQSClient({ region });

        // These would be configured via env vars but we mock them or provide defaults
        this.topicArn = (this.configService.get('EVENT_BUS_SNS_TOPIC_ARN') as string) || 'arn:aws:sns:us-east-1:123456789012:pbac-events';
        this.queueUrl = (this.configService.get('EVENT_BUS_SQS_QUEUE_URL') as string) || 'https://sqs.us-east-1.amazonaws.com/123456789012/pbac-events-queue';
    }

    async publish<T>(topic: string, message: T): Promise<void> {
        try {
            const command = new PublishCommand({
                TopicArn: this.topicArn,
                Message: JSON.stringify(message),
                MessageAttributes: {
                    'eventType': {
                        DataType: 'String',
                        StringValue: topic
                    }
                }
            });

            await this.snsClient.send(command);
            this.logger.debug(`[SnsSqsEventBus] Published event ${topic} to SNS`);
        } catch (error) {
            this.logger.error(`[SnsSqsEventBus] Failed to publish event ${topic}`, error);
            throw error;
        }
    }

    async subscribe<T>(topic: string, handler: (message: T) => Promise<void>): Promise<void> {
        this.logger.info(`[SnsSqsEventBus] Starting SQS poller for topic: ${topic}`);

        // Very basic long-polling implementation for the abstract adapter
        const poll = async () => {
            try {
                const command = new ReceiveMessageCommand({
                    QueueUrl: this.queueUrl,
                    MaxNumberOfMessages: 10,
                    WaitTimeSeconds: 20,
                    MessageAttributeNames: ['All']
                });

                const response = await this.sqsClient.send(command);

                if (response.Messages && response.Messages.length > 0) {
                    for (const msg of response.Messages) {
                        try {
                            const snsPayload = JSON.parse(msg.Body!);
                            // SNS wraps the actual message in a "Message" property
                            const eventType = snsPayload.MessageAttributes?.eventType?.Value;

                            // Only process messages that match the subscribed topic
                            if (eventType === topic) {
                                const parsedMessage = JSON.parse(snsPayload.Message) as T;
                                await handler(parsedMessage);
                            }

                            // Delete message after successful processing
                            await this.sqsClient.send(new DeleteMessageCommand({
                                QueueUrl: this.queueUrl,
                                ReceiptHandle: msg.ReceiptHandle!
                            }));
                        } catch (handlerErr) {
                            this.logger.error(`[SnsSqsEventBus] Error handling message`, handlerErr);
                            // Do not delete, let it go to DLQ
                        }
                    }
                }
            } catch (err) {
                this.logger.error(`[SnsSqsEventBus] Error polling SQS`, err);
            }

            // Loop recursively
            setTimeout(poll, 100);
        };

        // Start background polling
        poll();
    }
}
