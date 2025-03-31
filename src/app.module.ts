import { Module, OnModuleInit } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthModule } from './modules/auth/auth.module';
import { UserModule } from './modules/user/user.module';
import { RedisService } from './shared/services/redis.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { User } from './modules/user/user.entity';

@Module({
  imports: [
    /**
     * Loads variables from .env file (like MONGODB_URI, REDIS_HOST).
     * isGlobal: true means this module is available throughout the app
     */
    ConfigModule.forRoot({ envFilePath: '.env', isGlobal: true }),

    // * Connects to MongoDB
    // MongooseModule.forRoot(process.env.MONGODB_URI), this is optional either you choose to use Mongoose or TypORM module

    /**
     * TypeORM is an Object Relational Mapper (ORM) that helps manage MongoDB.
     * useFactory loads the database URL dynamically from .env.
     * synchronize: true automatically updates the database schema (for development only).
     */
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        type: 'mongodb',
        url: configService.get<string>('MONGODB_URI'),
        database: 'url-shortener',
        synchronize: true, // Set to false in production
        entities: [User],
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }),
    }),
    AuthModule,
    UserModule,
  ],
  providers: [RedisService],
})
export class AppModule implements OnModuleInit {
  constructor(private readonly dataSource: DataSource) {}

  async onModuleInit() {
    console.log(
      'Database Connection Status:',
      this.dataSource.isInitialized ? 'Connected ✅' : 'Not Connected ❌',
    );
  }
}
