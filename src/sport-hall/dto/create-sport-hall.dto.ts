import { ApiProperty } from '@nestjs/swagger';
import { IsNumber, IsPhoneNumber, IsString } from 'class-validator';

export class CreateSportHallDto {
  @ApiProperty({
    example: 'Sport hall',
    description: 'Sport hall name',
  })
  @IsString()
  name: string;

  @ApiProperty({
    example: '+998991234567',
    description: 'Sport hall phone number',
  })
  @IsPhoneNumber()
  phone: string;

  @ApiProperty({
    example: 'Tashkent',
    description: 'Sport hall location',
  })
  @IsString()
  location: string;

  @ApiProperty({
    example: 'For kids',
    description: 'Sport hall conditions',
  })
  @IsString()
  conditions: string;

  @ApiProperty({
    example: 'Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday',
    description: 'Sport hall work days',
  })
  @IsString()
  work_days: string;

  @ApiProperty({
    example: '10:00',
    description: 'Sport hall open time',
  })
  @IsString()
  open_time: string;

  @ApiProperty({
    example: '22:00',
    description: 'Sport hall close time',
  })
  @IsString()
  close_time: string;

  @ApiProperty({
    example: 'image.jpg',
    description: 'Sport hall image',
  })
  @IsString()
  image: string;
}
