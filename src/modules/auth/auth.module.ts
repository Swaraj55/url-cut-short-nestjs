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
import { EmailService } from 'src/shared/services/email.service';
import { MfaModule } from '../mfa/mfa.module';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';

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
    MfaModule,
    MailerModule.forRoot({
      transport: {
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      },
      defaults: {
        from: '"Your App" <no-reply@yourapp.com>',
      },
      template: {
        dir: process.cwd() + '/src/shared/templates',
        adapter: new HandlebarsAdapter(), // make sure you have this imported
        options: {
          strict: true,
        },
      },
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
    EmailService,
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
