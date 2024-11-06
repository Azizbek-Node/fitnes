import { ApiProperty } from '@nestjs/swagger';
import { IsNumber, IsString } from 'class-validator';

export class CreateNotificationDto {
  @ApiProperty({
    example: 1,
    description: 'Sport hall id',
  })
  @IsNumber()
  sportHallId: number;

  @ApiProperty({
    example: 'Hello',
    description: 'Message',
  })
  @IsString()
  message: string;
}
