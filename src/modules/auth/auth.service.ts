import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user/user.service';
import { RedisService } from '../../shared/services/redis.service';
import { HashUtil } from '../../shared/utils/hash.util';
import { RegisterDto, LoginDto } from '../../common/dto/auth.dto';
import { MfaService } from '../mfa/mfa.service';
import { User } from '../user/user.entity';
import { EmailService } from 'src/shared/services/email.service';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly configService: ConfigService,
    private readonly mfaService: MfaService,
    private readonly emailService: EmailService,
  ) {}

  async register(registerDto: RegisterDto) {
    if (!registerDto.agreeToTerms) {
      throw new BadRequestException(
        'You must agree to the terms and conditions',
      );
    }
    const hashedPassword = await HashUtil.hashPassword(registerDto.password);
    return this.userService.createUser({
      ...registerDto,
      password: hashedPassword,
    });
  }

  async login(loginDto: LoginDto) {
    const { email, password, mfaCode } = loginDto;

    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    const isPasswordValid = await HashUtil.comparePasswords(
      password,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    const mfa = user.mfa_details;
    const mfaType = mfa?.mfa_type;
    const mfaState = mfa?.mfa_state;
    const mfaSecret = mfa?.secret;
    // 1. MFA not enabled → Login directly
    if (!mfa || (!mfaType && !mfaState)) {
      return this.generateAndReturnTokens(user);
    }

    // 2. MFA enabled but not enrolled and no code → Start enrollment
    if (mfaState === 'unenrolled' && !mfaCode) {
      const updatedSecret = this.mfaService.generateSecret(
        user.email,
        user.username,
        user._id.toString(),
      );

      const updatedDetails = {
        ...mfa,
        secret: {
          ascii: updatedSecret.ascii,
          hex: updatedSecret.hex,
          base32: updatedSecret.base32,
          otpauth_url: updatedSecret.otpauth_url,
        },
      };

      await this.userService.updateMfaDetails(
        user._id.toString(),
        updatedDetails,
      );

      if (mfaType === 'TOTP') {
        const qrCode = await this.mfaService.generateQRCode(
          updatedSecret.otpauth_url,
        );
        return {
          status: 'MFA_ENROLLMENT_REQUIRED',
          mfa_type: mfaType,
          message:
            'Scan the QR code using your authenticator app and enter the verification code.',
          qrCode,
          secret: updatedSecret.base32,
        };
      }

      if (mfaType === 'EMAIL') {
        const code = this.mfaService.generateEmailToken(updatedSecret.base32);
        await this.emailService.sendTwoFactorCode(
          user.email,
          user.username,
          code,
        );
        return {
          status: 'MFA_ENROLLMENT_REQUIRED',
          mfa_type: mfaType,
          message:
            'A verification code has been sent to your email. Please enter it to complete MFA setup.',
        };
      }
    }

    // 3. MFA enabled but not enrolled → Verifying first-time code
    if (mfaState === 'unenrolled' && mfaCode) {
      const isVerified = this.mfaService.verifyTOTPCode(
        mfaSecret.base32,
        mfaCode,
      );
      if (!isVerified) {
        let errorMessage =
          'The verification code you entered is incorrect or has expired. Please check the code and try again.';
        if (user.mfa_details.mfa_type === 'EMAIL') {
          errorMessage =
            'The code sent to your email is incorrect or has expired. Please check your inbox and try again.';
        }

        throw new UnauthorizedException({
          status: 'MFA_VERIFICATION_FAILED',
          message: errorMessage,
        });
      }

      await this.userService.updateMfaDetails(user._id.toString(), {
        ...mfa,
        mfa_status: 'enabled',
        mfa_state: 'enrolled',
      });

      return {
        status: 'MFA_ENROLLMENT_COMPLETE',
        message:
          'Multi-factor authentication has been successfully set up. Please log in again to continue.',
        nextStep: 'LOGIN_VERIFICATION_REQUIRED',
      };
    }

    // 4. MFA enrolled
    if (mfaState === 'enrolled') {
      // No code provided: prompt + send email code if needed
      if (!mfaCode) {
        if (mfaType === 'EMAIL') {
          const code = this.mfaService.generateEmailToken(mfaSecret.base32);
          await this.emailService.sendTwoFactorCode(
            user.email,
            user.username,
            code,
          );
        }

        return {
          status: 'MFA_TOKEN_REQUIRED',
          mfa_type: mfaType,
          message: 'Please enter your MFA code to continue.',
        };
      }

      // Code provided: verify
      const isVerified = this.mfaService.verifyTOTPCode(
        mfaSecret.base32,
        mfaCode,
      );

      if (!isVerified) {
        if (mfaType === 'EMAIL') {
          // Re-send new code if verification fails
          const newCode = this.mfaService.generateEmailToken(mfaSecret.base32);
          await this.emailService.sendTwoFactorCode(
            user.email,
            user.username,
            newCode,
          );

          throw new UnauthorizedException({
            status: 'MFA_CODE_EXPIRED',
            message:
              'The code has expired or is incorrect. A new code has been sent to your email. Please try again with the new code.',
          });
        }

        throw new UnauthorizedException({
          status: 'MFA_VERIFICATION_FAILED',
          message:
            'The verification code you entered is incorrect or has expired. Please check your authenticator app and try again.',
        });
      }

      // Verified successfully
      return this.generateAndReturnTokens(user);
    }

    // Fallback (should never happen)
    throw new UnauthorizedException('Unexpected MFA state. Please try again.');
  }

  async refreshToken(userId: string, refreshToken: string) {
    const storedToken = await this.redisService.get(`refreshToken:${userId}`);
    if (!storedToken || storedToken !== refreshToken) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
    const user = await this.userService.findById(userId);
    if (!user) throw new UnauthorizedException('User not found');

    return {
      accessToken: this.generateAccessToken(user._id.toString(), user.email),
    };
  }

  async logout(userId: number) {
    await this.redisService.delete(`refreshToken:${userId}`);
  }

  private generateAccessToken(userId: string, email: string): string {
    return this.jwtService.sign(
      { userId, email },
      {
        secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
        expiresIn: '15m',
      },
    );
  }

  public generateRefreshToken(userId: string, email: string): string {
    return this.jwtService.sign(
      { userId, email },
      {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      },
    );
  }

  async validateOAuthLogin(oAuthUser) {
    let user = await this.userService.findByEmail(oAuthUser.email);
    if (!user) {
      // Create a new user if they don't exist
      user = await this.userService.createUser({
        username: oAuthUser.username,
        email: oAuthUser.email,
        provider: oAuthUser.provider,
        providerId: oAuthUser.providerId,
      });
    }

    const accessToken = this.jwtService.sign({
      userId: user._id.toString(),
      email: user.email,
    });
    return { user, accessToken };
  }

  async googleLogin(oAuthUser) {
    let user = await this.userService.findByEmail(oAuthUser.email);

    if (!user) {
      user = await this.userService.createUser({
        username: oAuthUser.username,
        email: oAuthUser.email,
        provider: oAuthUser.provider,
        providerId: oAuthUser.providerId,
      });
    }

    const accessToken = this.jwtService.sign({
      userId: user._id.toString(),
      email: user.email,
    });
    return { user, accessToken };
  }

  async twitterLogin(oAuthUser) {
    let user = await this.userService.findByEmail(oAuthUser.email);

    if (!user) {
      user = await this.userService.createUser({
        username: oAuthUser.username,
        email: oAuthUser.email,
        provider: oAuthUser.provider,
        providerId: oAuthUser.providerId,
      });
    }

    const accessToken = this.jwtService.sign({
      userId: user._id.toString(),
      email: user.email,
    });

    return { user, accessToken };
  }

  private generateAndReturnTokens(user: User) {
    const accessToken = this.generateAccessToken(
      user._id.toString(),
      user.email,
    );
    const refreshToken = this.generateRefreshToken(
      user._id.toString(),
      user.email,
    );

    // Store the refresh token in Redis for 7 days (default)
    this.redisService.set(
      `refreshToken:${user._id.toString()}`,
      refreshToken,
      7 * 24 * 60 * 60,
    );
    return { accessToken, refreshToken };
  }

  verifyRefreshToken(token: string): { userId: string; email: string } {
    try {
      const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET) as {
        userId: string;
        email: string;
      };
      return payload;
    } catch (err) {
      throw new UnauthorizedException('Invalid or expired refresh token', err);
    }
  }
}
