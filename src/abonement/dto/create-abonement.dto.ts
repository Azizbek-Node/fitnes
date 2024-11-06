import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsIn, IsInt, IsNumber, Min } from 'class-validator';

export class CreateAbonementDto {
  @ApiProperty({
    example: 1,
    description: 'Abonement duration',
  })
  @IsInt()
  @IsIn([1, 3, 6, 12], { message: "1, 3, 6, 12 dan birini tanlang" })
  duration: number;

  @ApiProperty({
    example: 3,
    description: 'Abonement client amount',
  })
  @IsInt()
  @Min(1, { message: "Client 0 bo`lishi mumkin emas" })
  clientAmount: number;

  @ApiProperty({
    example: true,
    description: 'Abonement is active',
  })
  @IsBoolean()
  isActive: boolean;

  @ApiProperty({
    example: 1000000,
    description: 'Abonement price',
  })
  @IsNumber()
  price: number;

  @ApiProperty({
    example: 1,
    description: 'Discount id',
  })
  @IsInt()
  discountId: number;
}
