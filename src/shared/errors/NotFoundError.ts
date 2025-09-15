import { BaseError } from './BaseError';

export class NotFoundError extends BaseError {
    constructor(message: string) {
        super('NotFoundError', 404, message);
    }
}