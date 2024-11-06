import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNumber, IsString } from 'class-validator';

export class CreateTrainerDto {
  @ApiProperty({
    example: 'John Doe',
    description: 'Trainer name',
  })
  @IsString()
  name: string;

  @ApiProperty({
    example: 'john@example.com',
    description: 'Trainer email',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: '123456',
    description: 'Password',
  })
  @IsString()
  password: string;

  @ApiProperty({
    example: '123456',
    description: 'Confirm password',
  })
  @IsString()
  confirm_password: string;

  @ApiProperty({
    example: '+998991234567',
    description: 'Trainer phone',
  })
  @IsString()
  phone: string;

  @ApiProperty({
    example: '1 year',
    description: 'Trainer experience',
  })
  @IsString()
  experience: string;

  @ApiProperty({
    example: 1,
    description: 'Sport hall id',
  })
  @IsNumber()
  sportHallId: number;
}
