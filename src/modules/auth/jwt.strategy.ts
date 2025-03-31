import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../../common/interfaces/jwt-payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: configService.get<string>('JWT_ACCESS_SECRET'),
    });

    if (!configService.get<string>('JWT_ACCESS_SECRET')) {
      throw new UnauthorizedException('JWT_ACCESS_SECRET is missing in .env');
    }
  }

  async validate(payload: JwtPayload) {
    return { userId: payload.userId, email: payload.email };
  }
}
