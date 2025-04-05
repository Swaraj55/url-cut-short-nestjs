// src/modules/auth/mfa/mfa.service.ts

import { Injectable } from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';

@Injectable()
export class MfaService {
  generateSecret(email: string, username: string, userId: string) {
    const secret = speakeasy.generateSecret();
    const otpauth_url = speakeasy.otpauthURL({
      secret: secret.ascii,
      label: `${userId}:${email}`,
      issuer: username,
    });
    return { ...secret, otpauth_url };
  }

  async generateQRCode(otpauthUrl: string) {
    return await qrcode.toDataURL(otpauthUrl);
  }

  verifyTOTPCode(base32Secret: string, code: string) {
    return speakeasy.totp.verify({
      secret: base32Secret,
      encoding: 'base32',
      token: code,
      window: 1,
    });
  }

  generateEmailToken(secret: string): string {
    return speakeasy.totp({
      secret,
      encoding: 'base32',
    });
  }
}
