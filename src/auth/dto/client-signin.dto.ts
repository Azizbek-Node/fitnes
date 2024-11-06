import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class ClientSigninDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
