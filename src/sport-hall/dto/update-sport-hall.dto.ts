import { PartialType } from '@nestjs/swagger';
import { CreateSportHallDto } from './create-sport-hall.dto';

export class UpdateSportHallDto extends PartialType(CreateSportHallDto) {}
