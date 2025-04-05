import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class EmailService {
  constructor(private readonly mailerService: MailerService) {}

  async sendTwoFactorEnrollment(email: string, username: string, totp: string) {
    return this.mailerService.sendMail({
      to: email,
      subject: '2FA Enrollment Required',
      template: 'enrollmentTwoFactor', // filename from templates/ folder
      context: {
        username,
        totp,
      },
    });
  }

  async sendTwoFactorCode(email: string, username: string, totp: string) {
    return this.mailerService.sendMail({
      to: email,
      subject: '2FA Code Required',
      template: 'enrolledTwoFactor',
      context: {
        username,
        totp,
      },
    });
  }
}
