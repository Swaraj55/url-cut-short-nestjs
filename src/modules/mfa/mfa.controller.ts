import {
  Controller,
  Post,
  Body,
  Req,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import { MfaService } from './mfa.service';
import { JwtAuthGuard } from 'src/shared/guard/jwt-auth.guard';
import { UserService } from 'src/modules/user/user.service';
import { EnableMfaDto } from 'src/common/dto/mfa.dto';
import * as speakeasy from 'speakeasy';
import { EmailService } from 'src/shared/services/email.service';

@Controller('mfa')
export class MfaController {
  constructor(
    private readonly mfaService: MfaService,
    private readonly userService: UserService,
    private readonly emailService: EmailService,
  ) {}

  @Post('enable')
  @UseGuards(JwtAuthGuard)
  async enableMfa(@Req() req, @Body() body: EnableMfaDto) {
    const { mfa_type } = body;
    const user = await this.userService.findById(req.user.userId);
    if (!user) throw new Error('User not found');

    // ❌ Prevent if MFA is already fully enrolled with a different type
    if (
      user.mfa_details?.mfa_status === 'enabled' &&
      user.mfa_details?.mfa_state === 'enrolled' &&
      user.mfa_details?.mfa_type !== mfa_type
    ) {
      throw new BadRequestException(
        `MFA is already enabled via ${user.mfa_details.mfa_type}. Please disable it before enabling a new method.`,
      );
    }

    // 🔁 Reset if previous MFA setup was incomplete with different type
    if (
      user.mfa_details?.mfa_status === 'disabled' &&
      user.mfa_details?.mfa_state === 'unenrolled' &&
      user.mfa_details?.mfa_type !== mfa_type
    ) {
      await this.userService.updateMfaDetails(user._id.toString(), {
        mfa_status: 'disabled',
        mfa_state: null,
        mfa_type: null,
        secret: null,
      });

      return {
        message: `Previous MFA setup using ${user.mfa_details.mfa_type} was incomplete and has been reset. You can now proceed to set up MFA using ${mfa_type}.`,
      };
    }

    // 🔐 Enable TOTP
    if (mfa_type === 'TOTP') {
      const secret = this.mfaService.generateSecret(
        user.email,
        user.username,
        user._id.toString(),
      );

      await this.userService.updateMfaDetails(user._id.toString(), {
        mfa_status: 'disabled',
        mfa_state: 'unenrolled',
        mfa_type: 'TOTP',
        secret: {
          ascii: secret.ascii,
          hex: secret.hex,
          base32: secret.base32,
          otpauth_url: secret.otpauth_url,
        },
      });

      // const qrCode = await this.mfaService.generateQRCode(secret.otpauth_url);
      return {
        status: 'MFA_SETUP_REQUIRED',
        mfa_type,
        message: 'MFA of type TOTP is enabled and ready for enrollment.',
      };
    }

    // 📧 Enable Email-based MFA
    if (mfa_type === 'EMAIL') {
      const secret = speakeasy.generateSecret();

      await this.userService.updateMfaDetails(user._id.toString(), {
        mfa_status: 'disabled',
        mfa_state: 'unenrolled',
        mfa_type: 'EMAIL',
        secret: {
          ascii: secret.ascii,
          hex: secret.hex,
          base32: secret.base32,
          otpauth_url: null,
        },
      });

      // const emailToken = this.mfaService.generateEmailToken(secret.base32);
      // await this.emailService.sendTwoFactorEnrollment(
      //   user.email,
      //   user.username,
      //   emailToken,
      // );

      return {
        status: 'MFA_SETUP_REQUIRED',
        mfa_type,
        message: 'MFA of type EMAIL is enabled and ready for enrollment.',
      };
    }

    // 📵 Not implemented
    if (mfa_type === 'SMS') {
      return { message: 'SMS MFA not implemented yet' };
    }

    throw new BadRequestException('Unsupported MFA type');
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

    return {
      status: 'MFA_DISABLED',
      message:
        'Multi-Factor Authentication has been successfully disabled for your account.',
    };
  }
}
