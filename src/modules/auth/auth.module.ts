import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserModule } from '../user/user.module';
import { JwtStrategy } from './jwt.strategy';
import { RefreshJwtStrategy } from './refresh-jwt.strategy';
import { RedisService } from '../../shared/services/redis.service';
import { GoogleStrategy } from './google.strategy';
import { MicrosoftStrategy } from './microsoft.strategy';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TwitterStrategy } from './twitter.startegy';

@Module({
  imports: [
    ConfigModule.forRoot(), // Ensure environment variables are loaded
    UserModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_ACCESS_SECRET'), // Load secret dynamically
        signOptions: { expiresIn: '15m' },
      }),
    }),
  ],
  providers: [
    AuthService,
    JwtStrategy,
    RefreshJwtStrategy,
    RedisService,
    GoogleStrategy,
    MicrosoftStrategy,
    TwitterStrategy,
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
