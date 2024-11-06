import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { SportHallReviewService } from './sport-hall_review.service';
import { CreateSportHallReviewDto } from './dto/create-sport-hall_review.dto';
import { UpdateSportHallReviewDto } from './dto/update-sport-hall_review.dto';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { LikeSportHallDto } from './dto/like-sportreview.dto';
@Controller('sport-hall-review')
@ApiTags('Sport Hall Review')
export class SportHallReviewController {
  constructor(
    private readonly sportHallReviewService: SportHallReviewService,
  ) {}

  @ApiOperation({
    summary: 'Create sport hall review',
    description: 'Create sport hall review',
  })
  @Post()
  create(@Body() createSportHallReviewDto: CreateSportHallReviewDto) {
    return this.sportHallReviewService.create(createSportHallReviewDto);
  }

  @ApiOperation({
    summary: 'Like sport hall',
    description: 'Like sport hall',
  })
  @Post('like')
  likeSportHall(@Body() likeSportHallDto: LikeSportHallDto) {
    return this.sportHallReviewService.likeSportHall(
      likeSportHallDto.clientId,
      likeSportHallDto.sportHallId,
    );
  }

  @ApiOperation({
    summary: 'Get all sport hall reviews',
    description: 'Get all sport hall reviews',
  })
  @Get()
  findAll() {
    return this.sportHallReviewService.findAll();
  }

  @ApiOperation({
    summary: 'Get sport hall review by id',
    description: 'Get sport hall review by id',
  })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.sportHallReviewService.findOne(+id);
  }

  @ApiOperation({
    summary: 'Update sport hall review',
    description: 'Update sport hall review',
  })
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateSportHallReviewDto: UpdateSportHallReviewDto,
  ) {
    return this.sportHallReviewService.update(+id, updateSportHallReviewDto);
  }

  @ApiOperation({
    summary: 'Delete sport hall review',
    description: 'Delete sport hall review',
  })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.sportHallReviewService.remove(+id);
  }
}
