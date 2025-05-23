// mfa.module.ts
import { Module } from '@nestjs/common';
import { MfaService } from './mfa.service';
import { MfaController } from './mfa.controller';
import { UserModule } from '../user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { EmailService } from 'src/shared/services/email.service';

@Module({
  imports: [UserModule, JwtModule.register({}), ConfigModule],
  providers: [MfaService, EmailService],
  controllers: [MfaController],
  exports: [MfaService],
})
export class MfaModule {}
