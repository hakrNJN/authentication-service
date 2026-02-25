import { Client, Pool } from 'pg';
import { injectable, inject } from 'tsyringe';
import { IConfigService } from '../../application/interfaces/IConfigService';
import { IEventBus } from '../../application/interfaces/IEventBus';
import { ILogger } from '../../application/interfaces/ILogger';
import { TYPES } from '../../shared/constants/types';

@injectable()
export class PostgresEventBus implements IEventBus {
    private pool: Pool;
    private tableName: string = 'pbac_event_queue';
    private initialized: boolean = false;

    constructor(
        @inject(TYPES.ConfigService) private configService: IConfigService,
        @inject(TYPES.Logger) private logger: ILogger
    ) {
        this.pool = new Pool({
            host: this.configService.get('EVENT_BUS_PG_HOST', 'localhost') as string,
            port: this.configService.getNumber('EVENT_BUS_PG_PORT', 5432) as number,
            user: this.configService.get('EVENT_BUS_PG_USER', 'postgres') as string,
            password: this.configService.get('EVENT_BUS_PG_PASSWORD', 'postgres') as string,
            database: this.configService.get('EVENT_BUS_PG_DB', 'pbac_auth') as string,
        });

        // Initialize table lazily but synchronously with the first call
        this.initTable().catch(err => {
            this.logger.error('[PostgresEventBus] Failed to initialize queue table', err);
        });
    }

    private async initTable(): Promise<void> {
        if (this.initialized) return;

        const createTableQuery = `
            CREATE TABLE IF NOT EXISTS ${this.tableName} (
                id SERIAL PRIMARY KEY,
                topic VARCHAR(255) NOT NULL,
                payload JSONB NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_${this.tableName}_topic_status ON ${this.tableName} (topic, status);
        `;

        try {
            await this.pool.query(createTableQuery);
            this.initialized = true;
            this.logger.info(`[PostgresEventBus] Queue table initialized: ${this.tableName}`);
        } catch (error) {
            throw new Error(`Failed to create Postgres event queue table: ${error}`);
        }
    }

    async publish<T>(topic: string, message: T): Promise<void> {
        if (!this.initialized) await this.initTable();

        const query = `
            INSERT INTO ${this.tableName} (topic, payload, status)
            VALUES ($1, $2, 'pending')
        `;

        try {
            await this.pool.query(query, [topic, JSON.stringify(message)]);
            this.logger.debug(`[PostgresEventBus] Published message to internal queue table for topic: ${topic}`);
        } catch (error) {
            this.logger.error(`[PostgresEventBus] Failed to publish message to topic ${topic}`, error);
            throw error;
        }
    }

    async subscribe<T>(topic: string, handler: (message: T) => Promise<void>): Promise<void> {
        if (!this.initialized) await this.initTable();

        this.logger.info(`[PostgresEventBus] Starting SKIP LOCKED poller for topic: ${topic}`);

        const pollIntervalMs = this.configService.getNumber('EVENT_BUS_PG_POLL_MS', 1000);

        const poll = async () => {
            let client: Client | null = null;
            try {
                client = await this.pool.connect() as any;

                // Fetch up to 10 pending events, locking them so other workers don't grab them
                const fetchQuery = `
                    SELECT id, payload 
                    FROM ${this.tableName}
                    WHERE topic = $1 AND status = 'pending'
                    ORDER BY created_at ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT 10
                `;

                await client!.query('BEGIN');
                const result = await client!.query(fetchQuery, [topic]);

                if (result.rows.length > 0) {
                    const idsToMarkProcessed: number[] = [];

                    for (const row of result.rows) {
                        try {
                            const payload = row.payload as T;
                            await handler(payload);
                            idsToMarkProcessed.push(row.id);
                        } catch (handlerErr) {
                            this.logger.error(`[PostgresEventBus] Error handling message id ${row.id}`, handlerErr);
                            // It remains locked until transaction rollback, then reverts to 'pending' naturally
                        }
                    }

                    // Mark successfully handled messages as 'processed' (or delete them to save space)
                    if (idsToMarkProcessed.length > 0) {
                        const deleteQuery = `
                            DELETE FROM ${this.tableName}
                            WHERE id = ANY($1::int[])
                        `;
                        await client!.query(deleteQuery, [idsToMarkProcessed]);
                    }
                }

                await client!.query('COMMIT');

            } catch (err) {
                if (client) await client.query('ROLLBACK');
                this.logger.error(`[PostgresEventBus] Error polling PostgreSQL queue`, err);
            } finally {
                if (client) (client as any).release();
            }

            // Loop recursively
            setTimeout(poll, pollIntervalMs);
        };

        // Start background polling
        poll();
    }
}
