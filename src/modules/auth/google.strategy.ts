import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    try {
      console.log('Profile....>>>>', profile);
      const { emails, displayName, id, provider } = profile;
      const user = {
        provider,
        providerId: id,
        email: emails[0].value,
        username: displayName,
      };

      const validatedUser = await this.authService.validateOAuthLogin(user);
      return done(null, validatedUser);
    } catch (error) {
      console.error('Google OAuth validation error:', error);
      return done(error, false);
    }
  }
}
