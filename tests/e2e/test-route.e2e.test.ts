process.env.NODE_ENV = 'test';
process.env.REDIS_URL = 'redis://192.168.2.252:6379';
process.env.USE_REDIS_BLACKLIST = 'true';
process.env.SHARED_SECRET = 'test-shared-secret-e2e';

import request from 'supertest';
import { Express } from 'express';
import { createApp } from '../../src/app';
import { container } from 'tsyringe';
import { MockCognitoAdapter } from './setup/mockCognitoAdapter';
import { TYPES } from '../../src/shared/constants/types';
import { IAuthAdapter } from '../../src/application/interfaces/IAuthAdapter';

describe('Test Route E2E', () => {
  let app: Express & { shutdown?: () => Promise<void> };

  beforeAll(async () => {
    // Use mock cognito adapter
    container.clearInstances();
    container.registerInstance<IAuthAdapter>(TYPES.AuthAdapter, new MockCognitoAdapter());
    
    // Create app instance
    app = createApp();
  });

  afterAll(async () => {
    try {
      // Shutdown app gracefully (closes Redis connections)
      if (app && app.shutdown) {
        await app.shutdown();
      }
      
      // Wait a bit for cleanup
      await new Promise(resolve => setTimeout(resolve, 100));
    } catch (error) {
      console.error('Error during test cleanup:', error);
    }
  });

  it('should hit the /api/test route', async () => {
    const response = await request(app).get('/api/test');
    expect(response.status).toBe(200);
    expect(response.text).toBe('Test route hit!');
  });
});