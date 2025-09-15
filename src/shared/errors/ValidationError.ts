import { BaseError } from './BaseError';

export class ValidationError extends BaseError {
  constructor(message: string = 'Validation Error', details?: any) {
    super('ValidationError', 400, message, true);
  }
}
