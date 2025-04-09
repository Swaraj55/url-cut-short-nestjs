import {
  IsEmail,
  IsNotEmpty,
  MinLength,
  IsOptional,
  IsEnum,
  ValidateIf,
  IsBoolean,
} from 'class-validator';

export enum AuthProvider {
  LOCAL = 'local',
  GOOGLE = 'google',
  MICROSOFT = 'microsoft',
}

export class RegisterDto {
  @IsNotEmpty()
  username: string;

  @IsEmail()
  email: string;

  @ValidateIf((dto) => dto.provider === AuthProvider.LOCAL)
  @IsNotEmpty({ message: 'Password is required for local users' })
  @MinLength(6, { message: 'Password must be at least 6 characters long' })
  password?: string;

  @IsEnum(AuthProvider)
  @IsOptional()
  provider?: AuthProvider;

  @ValidateIf((dto) => dto.provider !== AuthProvider.LOCAL)
  @IsNotEmpty({ message: 'Provider ID is required for OAuth users' })
  providerId?: string;

  @IsOptional()
  mfaEnabled?: boolean;

  @IsOptional()
  mfaCode?: string;

  @IsOptional()
  accountCreatedDate?: Date;

  @IsOptional()
  @IsBoolean()
  @IsNotEmpty({ message: 'You must agree to the terms and conditions' })
  agreeToTerms?: boolean;
}

export class LoginDto {
  @IsEmail()
  email: string;

  @IsOptional()
  password?: string; // Optional for OAuth users

  @IsEnum(AuthProvider)
  provider: AuthProvider; // Required to differentiate between local and OAuth login

  @IsOptional()
  mfaCode?: string; // If MFA is enabled, the user must provide the code

  @IsOptional()
  rememberMe?: boolean;
}
