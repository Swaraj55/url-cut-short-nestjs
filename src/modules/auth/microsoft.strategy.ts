import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-microsoft';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MicrosoftStrategy extends PassportStrategy(Strategy, 'microsoft') {
  constructor(private configService: ConfigService) {
    super({
      clientID: configService.get<string>('MICROSOFT_CLIENT_ID'),
      clientSecret: configService.get<string>('MICROSOFT_CLIENT_SECRET'),
      callbackURL: configService.get<string>('MICROSOFT_CALLBACK_URL'),
      scope: ['user.read'],
      tenant: 'common', // Allows both personal & work accounts
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: (error: any, user?: any) => void, // ✅ Correct type
  ): Promise<any> {
    try {
      const { id, displayName, emails } = profile;

      const user = {
        providerId: id,
        provider: 'microsoft',
        email: emails?.[0]?.value || '',
        username: displayName,
        accessToken,
        refreshToken,
      };

      done(null, user);
    } catch (error) {
      done(error, null);
    }
  }
}
