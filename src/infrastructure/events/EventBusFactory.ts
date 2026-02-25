import { container } from 'tsyringe';
import { IConfigService } from '../../application/interfaces/IConfigService';
import { IEventBus } from '../../application/interfaces/IEventBus';
import { TYPES } from '../../shared/constants/types';
import { RabbitMqEventBus } from './RabbitMqEventBus';
import { SnsSqsEventBus } from './SnsSqsEventBus';
import { PostgresEventBus } from './PostgresEventBus';
import { ILogger } from '../../application/interfaces/ILogger';

export class EventBusFactory {
    static createEventBus(): IEventBus {
        const configService = container.resolve<IConfigService>(TYPES.ConfigService);
        const logger = container.resolve<ILogger>(TYPES.Logger);

        const providerRaw = configService.get('EVENT_BUS_PROVIDER');
        const provider = (typeof providerRaw === 'string' ? providerRaw : 'RABBITMQ').toUpperCase();

        if (provider === 'SNS_SQS') {
            logger.info('[EventBusFactory] Initializing SNS/SQS Event Bus Adapter');
            return new SnsSqsEventBus(configService, logger);
        } else if (provider === 'POSTGRES') {
            logger.info('[EventBusFactory] Initializing PostgreSQL Event Bus Adapter');
            return new PostgresEventBus(configService, logger);
        } else {
            logger.info('[EventBusFactory] Initializing RabbitMQ Event Bus Adapter');
            return new RabbitMqEventBus(configService, logger);
        }
    }
}
