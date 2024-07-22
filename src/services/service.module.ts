import { Module } from '@nestjs/common';
import { redisClientProvider } from 'src/configs';
import RedisService from './redis.service';
import CommunicationService from './communication.service';

@Module({
  providers: [redisClientProvider, RedisService, CommunicationService],
  exports: [RedisService, CommunicationService],
})
export class ServiceModule {}
