import { PartialType } from '@nestjs/swagger';
import { CreateSportHallReviewDto } from './create-sport-hall_review.dto';

export class UpdateSportHallReviewDto extends PartialType(CreateSportHallReviewDto) {}
