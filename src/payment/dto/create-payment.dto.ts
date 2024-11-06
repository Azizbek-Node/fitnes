import { ApiProperty } from '@nestjs/swagger';

export class CreatePaymentDto {
  @ApiProperty({
    example: 1,
    description: 'Abonement ID',
  })
  abonementId: number;

  @ApiProperty({
    example: 'paid',
    description: 'To`kiladigan status(paid, unpaid)',
  })
  status: string;

  @ApiProperty({
    example: 'card',
    description: 'Tolanadigan usul',
  })
  method: string;
}
