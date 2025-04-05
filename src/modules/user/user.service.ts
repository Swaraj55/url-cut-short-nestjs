import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { RegisterDto } from 'src/common/dto/auth.dto';
import { ObjectId } from 'mongodb';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async findById(id: string): Promise<User | null> {
    console.log('findById', new ObjectId(id));
    return this.userRepository.findOne({
      where: { _id: new ObjectId(id) },
    });
  }

  async createUser(registerDto: RegisterDto): Promise<User> {
    try {
      const newUser = this.userRepository.create(registerDto);
      return await this.userRepository.save(newUser);
    } catch (error) {
      // MongoDB duplicate key error
      console.log(error);
      if (error.code === 11000) {
        throw new ConflictException(
          'User with this email or username already exists.',
        );
      }

      console.error('Unexpected error in createUser:', error);
      throw new InternalServerErrorException(
        'Something went wrong while creating user.',
      );
    }
  }

  async updateMfaDetails(
    userId: string,
    mfaDetails: Partial<User['mfa_details']>,
  ) {
    const user = await this.findById(userId);
    if (!user) throw new Error('User not found');

    user.mfaEnabled = mfaDetails.mfa_status === 'enabled';
    user.mfa_details = { ...user.mfa_details, ...mfaDetails };
    return this.userRepository.save(user);
  }
}

export default UserService;
