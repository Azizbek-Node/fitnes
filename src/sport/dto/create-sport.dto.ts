import { IsNotEmpty, IsString } from 'class-validator';

import { ApiProperty } from '@nestjs/swagger';

export class CreateSportDto {
  @ApiProperty({
    example: 'Futbol',
    description: 'Sport nomi',
  })
  @IsString()
  @IsNotEmpty()
  name: string;
}
