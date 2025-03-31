import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService {
  private client: Redis;

  constructor(private configService: ConfigService) {
    this.client = new Redis({
      host: this.configService.get<string>('REDIS_HOST', 'localhost'),
      port: this.configService.get<number>('REDIS_PORT', 6379),
    });

    this.client.on('connect', () => {
      console.log('✅ Redis connected successfully');
    });

    this.client.on('error', (err) => {
      console.error('❌ Redis connection error:', err);
    });

    // this.testRedis();
  }

  async set(key: string, value: string, expiresIn: number): Promise<void> {
    await this.client.set(key, value, 'EX', expiresIn);
  }

  async get(key: string): Promise<string | null> {
    return await this.client.get(key);
  }

  async delete(key: string): Promise<number> {
    return await this.client.del(key);
  }

  async testRedis() {
    try {
      await this.set('testKey', 'testValue', 3600);
      const value = await this.get('testKey');
      console.log('✅ Redis test passed. Retrieved:', value);
    } catch (err) {
      console.error('❌ Redis test failed:', err);
    }
  }
}
