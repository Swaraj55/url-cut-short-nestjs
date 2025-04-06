import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Res,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto } from '../../common/dto/auth.dto';
import { JwtAuthGuard } from '../../shared/guard/jwt-auth.guard';
import { AuthGuard } from '@nestjs/passport';
import { Response, Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(loginDto);

    if ('refreshToken' in result) {
      const { accessToken, refreshToken } = result;

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true, // only true in production
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      return { accessToken };
    }

    return result;
  }

  @Post('refresh-token')
  async refreshToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies['refreshToken'];
    if (!refreshToken) throw new UnauthorizedException('Refresh token missing');

    const payload = await this.authService.verifyRefreshToken(refreshToken);
    const newAccessToken = await this.authService.refreshToken(
      payload.userId,
      refreshToken,
    );

    // Optionally rotate refresh token
    const newRefreshToken = await this.authService.generateRefreshToken(
      payload.userId,
      payload.email,
    );

    // 1. Protecting the Refresh Token from XSS
    /**
     * Setting httpOnly: true means JavaScript in the browser cannot access the cookie (e.g., document.cookie).
     * This protects your refresh token from cross-site scripting (XSS) attacks.
     */
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { accessToken: newAccessToken };
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  logout(@Req() req) {
    return this.authService.logout(req.user.userId);
  }

  // ===== GOOGLE AUTH =====
  @Get('google')
  @UseGuards(AuthGuard('google'))
  googleLogin() {
    // Redirects to Google login page
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req) {
    return this.authService.validateOAuthLogin(req.user);
  }

  // ===== MICROSOFT AUTH =====
  @Get('microsoft')
  @UseGuards(AuthGuard('microsoft'))
  microsoftLogin() {
    // Redirects to Microsoft login page
  }

  @Get('microsoft/callback')
  @UseGuards(AuthGuard('microsoft'))
  async microsoftAuthRedirect(@Req() req) {
    return this.authService.validateOAuthLogin(req.user);
  }

  @Get('twitter')
  @UseGuards(AuthGuard('twitter'))
  twitterLogin() {
    // Redirects to Twitter login page
  }

  @Get('twitter/callback')
  @UseGuards(AuthGuard('twitter'))
  async twitterCallback(@Req() req) {
    return this.authService.validateOAuthLogin(req.user);
  }
}
