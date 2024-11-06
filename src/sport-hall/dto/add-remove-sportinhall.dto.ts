import { IsNumber } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
export class AddRemoveSportinhallDto {
  @ApiProperty({
    example: 1,
    description: 'Sport id',
  })
  @IsNumber()
  sportId: number;

  @ApiProperty({
    example: 1,
    description: 'Sport hall id',
  })
  @IsNumber()
  sportHallId: number;
}
