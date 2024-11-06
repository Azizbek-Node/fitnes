import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNumber, IsString } from 'class-validator';

export class CreateClientDto {
  @ApiProperty({
    example: 1,
    description: 'Abonement ID',
  })
  @IsNumber()
  abonementId: number;

  @ApiProperty({
    example: 1,
    description: 'Notification ID',
  })
  @IsNumber()
  notificationId: number;

  @ApiProperty({
    example: 'Azizbek',
    description: "Client's first name",
  })
  @IsString()
  fname: string;

  @ApiProperty({
    example: 'To`raxonov',
    description: "Client's last name",
  })
  @IsString()
  lname: string;

  @ApiProperty({
    example: 'azizbek@gmail.com',
    description: "Client's email",
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: '1234567890',
    description: "Client's password",
  })
  @IsString()
  password: string;

  @ApiProperty({
    example: '1234567890',
    description: "Client's confirm password",
  })
  @IsString()
  confirm_password: string;

  @ApiProperty({
    example: '+998901234567',
    description: "Client's phone number",
  })
  @IsString()
  phone: string;

  @ApiProperty({
    example: 'male',
    description: "Client's gender",
  })
  @IsString()
  gender: string;

  @ApiProperty({
    example: 20,
    description: 'Client age',
  })
  @IsNumber()
  age: number;
}
