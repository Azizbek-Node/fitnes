import { ApiProperty } from '@nestjs/swagger';

export class CreateLimitedDto {
  @ApiProperty({
    example: 1,
    description: 'Sport hall id',
  })
  sportHallId: number;

  @ApiProperty({
    example: '2024-01-01',
    description: 'Date',
  })
  date: Date;

  @ApiProperty({
    example: '10:00',
    description: 'Start time',
  })
  startTime: string;

  @ApiProperty({
    example: '14:00',
    description: 'End time',
  })
  endTime: string;
}
