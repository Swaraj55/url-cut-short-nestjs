import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user/user.service';
import { RedisService } from '../../shared/services/redis.service';
import { HashUtil } from '../../shared/utils/hash.util';
import { RegisterDto, LoginDto } from '../../common/dto/auth.dto';
import { MfaService } from '../mfa/mfa.service';
import { User } from '../user/user.entity';
import { EmailService } from 'src/shared/services/email.service';

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
    const hashedPassword = await HashUtil.hashPassword(registerDto.password);
    return this.userService.createUser({
      ...registerDto,
      password: hashedPassword,
    });
  }

  async login(loginDto: LoginDto) {
    const { email, password, mfaCode } = loginDto;
    const user = await this.userService.findByEmail(email);
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const isPasswordValid = await HashUtil.comparePasswords(
      password,
      user.password,
    );
    if (!isPasswordValid)
      throw new UnauthorizedException('Invalid credentials');

    const mfa = user.mfa_details;
    const mfaType = mfa?.mfa_type;
    const mfaState = mfa?.mfa_state;
    const mfaSecret = mfa?.secret;

    // 1. MFA Not Enabled → Login directly
    if (!mfa || mfa.mfa_status !== 'enabled') {
      return this.generateAndReturnTokens(user);
    }

    // 2. MFA Enabled but not enrolled and no TOTP/email code → Start enrollment
    if (mfaState === 'unenrolled' && !mfaCode) {
      const updatedSecret = this.mfaService.generateSecret(
        user.email,
        user.username,
        user._id.toString(),
      );
      const updatedDetails = {
        ...mfa,
        secret: updatedSecret,
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
          qrCode,
          secret: updatedSecret.base32,
        };
      }

      if (mfaType === 'Email') {
        const code = this.mfaService.generateEmailToken(updatedSecret); // implement this
        await this.emailService.sendTwoFactorCode(
          user.email,
          user.username,
          code,
        );
        return {
          status: 'MFA_ENROLLMENT_REQUIRED',
          mfa_type: mfaType,
          message: 'Verification code sent to email',
        };
      }
    }

    // 3. MFA Enabled but not enrolled → Verifying first-time code
    if (mfaState === 'unenrolled' && mfaCode) {
      const verified = this.mfaService.verifyTOTPCode(
        mfaSecret.base32,
        mfaCode,
      );
      if (!verified) throw new UnauthorizedException('Invalid MFA code');

      const updatedDetails = {
        ...mfa,
        mfa_state: 'enrolled',
      };
      delete updatedDetails.secret; // Optional: clean it
      await this.userService.updateMfaDetails(
        user._id.toString(),
        updatedDetails,
      );
      return {
        status: 'MFA_ENROLLMENT_COMPLETE',
        message: 'MFA enrollment successful. Please login again.',
      };
    }

    // 4. MFA Enrolled but no code → Prompt for token
    if (mfaState === 'enrolled' && !mfaCode) {
      if (mfaType === 'Email') {
        const code = this.mfaService.generateEmailToken(mfaSecret.base32);
        await this.emailService.sendTwoFactorEnrollment(
          user.email,
          user.username,
          code,
        );
      }

      return {
        status: 'MFA_TOKEN_REQUIRED',
        mfa_type: mfaType,
        message: 'MFA code required to login',
      };
    }

    // 5. MFA Enrolled and code present → Verify
    if (mfaState === 'enrolled' && mfaCode) {
      const verified = this.mfaService.verifyTOTPCode(
        mfaSecret.base32,
        mfaCode,
      );
      if (!verified) throw new UnauthorizedException('Invalid MFA code');

      return this.generateAndReturnTokens(user);
    }
  }

  async refreshToken(userId: string, refreshToken: string) {
    const storedToken = await this.redisService.get(`refreshToken:${userId}`);
    if (!storedToken || storedToken !== refreshToken) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
    console.log('Refreshing token', userId);
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

  private generateRefreshToken(userId: string, email: string): string {
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
}
