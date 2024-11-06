import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsEmail,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

export class CreateAdminDto {
  @ApiProperty({
    example: 'Admin',
    description: "Admin's name",
  })
  @IsOptional()
  @IsString()
  readonly name: string;

  @ApiProperty({
    example: 'admin@example.com',
    description: "Admin's email",
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: 'adminpassword',
    description: "Admin's password",
  })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({
    example: 'adminconfirmpassword',
    description: "Admin's confirm password",
  })
  @IsString()
  @MinLength(6)
  confirm_password: string;
}
