import { IsEnum, IsNotEmpty } from 'class-validator';

export enum MfaType {
  TOTP = 'TOTP',
  EMAIL = 'EMAIL',
  SMS = 'SMS',
}

export class EnableMfaDto {
  @IsEnum(MfaType)
  @IsNotEmpty()
  mfa_type: MfaType;
}
