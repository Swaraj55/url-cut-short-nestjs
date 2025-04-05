// src/modules/auth/mfa/mfa.controller.ts

import { Controller, Post, Body, Req, UseGuards } from '@nestjs/common';
import { MfaService } from './mfa.service';
import { JwtAuthGuard } from 'src/shared/guard/jwt-auth.guard';
import { UserService } from 'src/modules/user/user.service';
import { EnableMfaDto } from 'src/common/dto/mfa.dto';

@Controller('mfa')
export class MfaController {
  constructor(
    private readonly mfaService: MfaService,
    private readonly userService: UserService,
  ) {}

  @Post('enable')
  @UseGuards(JwtAuthGuard)
  async enableMfa(@Req() req, @Body() body: EnableMfaDto) {
    const { mfa_type } = body;
    const user = await this.userService.findById(req.user.userId);
    if (!user) throw new Error('User not found');

    if (mfa_type === 'TOTP') {
      const secret = this.mfaService.generateSecret(
        user.email,
        user.username,
        user._id.toString(),
      );

      await this.userService.updateMfaDetails(user._id.toString(), {
        mfa_status: 'disabled',
        mfa_state: 'pending',
        mfa_type: 'TOTP',
        secret: {
          ascii: secret.ascii,
          hex: secret.hex,
          base32: secret.base32,
          otpauth_url: secret.otpauth_url,
        },
      });

      const qrCode = await this.mfaService.generateQRCode(secret.otpauth_url);
      return { qrCode, secret: secret.base32 };
    }

    if (mfa_type === 'EMAIL') {
      // TODO: Implement email code generation & send email here
      await this.userService.updateMfaDetails(user._id.toString(), {
        mfa_status: 'disabled',
        mfa_state: 'pending',
        mfa_type: 'EMAIL',
      });

      return { message: 'Email MFA initiation is pending implementation' };
    }

    if (mfa_type === 'SMS') {
      // TODO: Implement SMS code generation & sending
      return { message: 'SMS MFA not implemented yet' };
    }

    throw new Error('Unsupported MFA type');
  }

  @Post('verify')
  @UseGuards(JwtAuthGuard)
  async verifyMfa(@Req() req, @Body() { code }: { code: string }) {
    const user = await this.userService.findById(req.user.userId);
    const secret = user?.mfa_details?.secret;

    if (!user || !secret) throw new Error('MFA not enabled');

    const isValid = this.mfaService.verifyTOTPCode(secret.base32, code);
    if (!isValid) throw new Error('Invalid TOTP code');

    await this.userService.updateMfaDetails(user._id.toString(), {
      mfa_status: 'enabled',
      mfa_state: 'enrolled',
    });

    return { message: 'MFA verified successfully' };
  }

  @Post('disable')
  @UseGuards(JwtAuthGuard)
  async disableMfa(@Req() req) {
    await this.userService.updateMfaDetails(req.user.userId, {
      mfa_status: 'disabled',
      mfa_state: null,
      mfa_type: null,
      secret: null,
    });

    return { message: 'MFA disabled' };
  }
}
