import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
} from 'typeorm';

@Entity() // Ensure this is a TypeORM entity
export class User {
  @PrimaryGeneratedColumn('uuid')
  _id: string;

  @Column({ unique: true })
  username: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ nullable: true })
  refreshToken?: string;

  @CreateDateColumn() // Automatically sets creation date
  accountCreatedDate: Date;

  @Column({ default: 'local' }) // 'local', 'google', 'microsoft'
  provider: string;

  @Column({ default: false })
  mfaEnabled: boolean;

  @Column('json', { default: { mfa_status: 'disabled' } })
  mfa_details: {
    mfa_status: string; // 'enabled' | 'disabled'
    mfa_state?: string; // 'enrolled' | 'pending' | null
    mfa_type?: string; // 'TOTP' | 'SMS' | 'EMAIL'
    secret?: {
      ascii: string;
      hex: string;
      base32: string;
      otpauth_url: string;
    };
  };
}
