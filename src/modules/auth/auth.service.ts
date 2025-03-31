import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user/user.service';
import { RedisService } from '../../shared/services/redis.service';
import { HashUtil } from '../../shared/utils/hash.util';
import { RegisterDto, LoginDto } from '../../common/dto/auth.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly configService: ConfigService,
  ) {}

  async register(registerDto: RegisterDto) {
    const hashedPassword = await HashUtil.hashPassword(registerDto.password);
    return this.userService.createUser({
      ...registerDto,
      password: hashedPassword,
    });
  }

  async login(loginDto: LoginDto) {
    const user = await this.userService.findByEmail(loginDto.email);
    if (
      !user ||
      !(await HashUtil.comparePasswords(loginDto.password, user.password))
    ) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const accessToken = this.generateAccessToken(user._id, user.email);
    const refreshToken = this.generateRefreshToken(user._id, user.email);

    await this.redisService.set(
      `refreshToken:${user._id}`,
      refreshToken,
      7 * 24 * 60 * 60,
    );

    return { accessToken, refreshToken };
  }

  async refreshToken(userId: string, refreshToken: string) {
    const storedToken = await this.redisService.get(`refreshToken:${userId}`);
    if (!storedToken || storedToken !== refreshToken) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const user = await this.userService.findById(userId);
    if (!user) throw new UnauthorizedException('User not found');

    return { accessToken: this.generateAccessToken(user._id, user.email) };
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
      userId: user._id,
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
      userId: user._id,
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
      userId: user._id,
      email: user.email,
    });

    return { user, accessToken };
  }
}
