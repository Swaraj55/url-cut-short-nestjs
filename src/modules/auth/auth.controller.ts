import { Controller, Post, Get, Body, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto } from '../../common/dto/auth.dto';
import { JwtAuthGuard } from '../../shared/guard/jwt-auth.guard';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('refresh-token')
  refreshToken(@Body() { userId, refreshToken }) {
    return this.authService.refreshToken(userId, refreshToken);
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
