import { ApiProperty } from '@nestjs/swagger';
import { IsNumber } from 'class-validator';

export class LikeSportHallDto {
  @ApiProperty({
    example: 1,
    description: 'Client ID',
  })
  @IsNumber()
  clientId: number;
  @ApiProperty({
    example: 1,
    description: 'Sport Hall ID',
  })
  sportHallId: number;
}
