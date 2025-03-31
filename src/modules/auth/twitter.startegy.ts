import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-twitter';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';

@Injectable()
export class TwitterStrategy extends PassportStrategy(Strategy, 'twitter') {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {
    super({
      consumerKey: configService.get<string>('TWITTER_CLIENT_ID'),
      consumerSecret: configService.get<string>('TWITTER_CLIENT_SECRET'),
      callbackURL: configService.get<string>('TWITTER_CALLBACK_URL'),
      includeEmail: true,
    });
  }

  async validate(token: string, tokenSecret: string, profile: any) {
    return this.authService.validateOAuthLogin({
      provider: 'twitter',
      providerId: profile.id,
      username: profile.username,
      email: profile.emails?.[0]?.value || null,
    });
  }
}
