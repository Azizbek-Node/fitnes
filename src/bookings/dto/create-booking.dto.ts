import { IsBoolean, IsNumber, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
export class CreateBookingDto {
  @ApiProperty({
    example: 1,
    description: 'Sport id',
  })
  @IsNumber()
  sportId: number;

  @ApiProperty({
    example: 1,
    description: 'Client id',
  })
  @IsNumber()
  clientId: number;

  @ApiProperty({
    example: '2024-01-01',
    description: 'Date',
  })
  @IsString()
  date: string;

  @ApiProperty({
    example: true,
    description: 'Is booked',
  })
  @IsBoolean()
  isBooked: boolean;
}
