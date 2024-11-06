import { ApiProperty } from '@nestjs/swagger';
import { IsNumber, IsString } from 'class-validator';

export class CreateDiscountDto {
  @ApiProperty({
    example: 10,
    description: 'Discount amount',
  })
  @IsNumber()
  amount: number;

  @ApiProperty({
    example: 10,
    description: 'Discount description',
  })
  @IsNumber()
  description: number;
}
