import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { RegisterDto } from 'src/common/dto/auth.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async findById(id: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { _id: id } });
  }

  async createUser(registerDto: RegisterDto): Promise<User> {
    try {
      const newUser = this.userRepository.create(registerDto);
      return await this.userRepository.save(newUser);
    } catch (error) {
      if (error.code === 11000) {
        throw new ConflictException('Username or email already exists.');
      }
      throw new InternalServerErrorException('Something went wrong.');
    }
  }
}

export default UserService;
