import { IsNumber, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
export class CreateSportHallReviewDto {
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
  @IsNumber()
  sportHallId: number;

  @ApiProperty({
    example: 'Good',
    description: 'Comment',
  })
  @IsString()
  comment: string;

  @ApiProperty({
    example: 1,
    description: 'Likes',
  })
  @IsNumber()
  likes: number;
}
