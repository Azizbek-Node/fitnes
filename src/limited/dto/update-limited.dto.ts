import { PartialType } from '@nestjs/swagger';
import { CreateLimitedDto } from './create-limited.dto';

export class UpdateLimitedDto extends PartialType(CreateLimitedDto) {}
