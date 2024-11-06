import { ApiProperty } from '@nestjs/swagger';
import { IsNumber, IsString } from 'class-validator';

export class CreateFeedbackDto {
  @ApiProperty({
    example: 1,
    description: 'Trainer id',
  })
  @IsNumber()
  trainerId: number;

  @ApiProperty({
    example: 1,
    description: 'Client id',
  })
  @IsNumber()
  clientId: number;

  @ApiProperty({
    example: 5,
    description: 'Stars from 1 to 5',
  })
  @IsNumber()
  stars: number;

  @ApiProperty({
    example: 'Good trainer',
    description: 'Feedback comment',
  })
  @IsString()
  comment: string;
}
