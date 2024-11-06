import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
} from '@nestjs/common';
import { FeedbackService } from './feedback.service';
import { CreateFeedbackDto } from './dto/create-feedback.dto';
import { UpdateFeedbackDto } from './dto/update-feedback.dto';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AdminGuard } from '../common/guards';

@ApiTags('Feedback')
@UseGuards(AdminGuard)
@Controller('feedback')
export class FeedbackController {
  constructor(private readonly feedbackService: FeedbackService) {}

  @ApiOperation({
    summary: 'Create feedback',
    description: 'Create feedback for trainer',
  })
  @Post()
  create(@Body() createFeedbackDto: CreateFeedbackDto) {
    return this.feedbackService.create(createFeedbackDto);
  }

  @ApiOperation({
    summary: 'Get all feedbacks',
    description: 'Get all feedbacks',
  })
  @Get()
  findAll() {
    return this.feedbackService.findAll();
  }

  @ApiOperation({
    summary: 'Get feedback by id',
    description: 'Get feedback by id',
  })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.feedbackService.findOne(+id);
  }

  @ApiOperation({
    summary: 'Update feedback by id',
    description: 'Update feedback by id',
  })
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateFeedbackDto: UpdateFeedbackDto,
  ) {
    return this.feedbackService.update(+id, updateFeedbackDto);
  }

  @ApiOperation({
    summary: 'Delete feedback by id',
    description: 'Delete feedback by id',
  })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.feedbackService.remove(+id);
  }
}
