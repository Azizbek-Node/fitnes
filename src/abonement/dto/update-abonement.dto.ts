import { PartialType } from '@nestjs/swagger';
import { CreateAbonementDto } from './create-abonement.dto';

export class UpdateAbonementDto extends PartialType(CreateAbonementDto) {}
