import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

export class TokenUtil {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  generateAccessToken(userId: number, email: string): string {
    return this.jwtService.sign(
      { userId, email },
      {
        secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
        expiresIn: '15m',
      },
    );
  }

  generateRefreshToken(userId: number, email: string): string {
    return this.jwtService.sign(
      { userId, email },
      {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      },
    );
  }
}
