import { ApiProperty } from '@nestjs/swagger';
import { IsNumber } from 'class-validator';

export class CreateProgressDto {
  @ApiProperty({
    example: 1,
    description: 'Client id',
  })
  @IsNumber()
  clientId: number;

  @ApiProperty({
    example: 60,
    description: 'Weight',
  })
  @IsNumber()
  weight: number;

  @ApiProperty({
    example: 14.5,
    description: 'Body fat percentage',
  })
  @IsNumber()
  bodyFatPercentage: number;

  @ApiProperty({
    example: 10,
    description: 'Muscle mass',
  })
  @IsNumber()
  muscleMass: number;
}
