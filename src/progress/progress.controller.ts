import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { ProgressService } from './progress.service';
import { CreateProgressDto } from './dto/create-progress.dto';
import { UpdateProgressDto } from './dto/update-progress.dto';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import Progress from './models/progress.model';

@Controller('progress')
export class ProgressController {
  constructor(private readonly progressService: ProgressService) {}

  @ApiOperation({
    summary: 'Create progress',
    description: 'Create progress',
  })
  @ApiResponse({ status: 200, type: Progress })
  @Post()
  create(@Body() createProgressDto: CreateProgressDto) {
    return this.progressService.create(createProgressDto);
  }

  @ApiOperation({
    summary: 'Get all progress',
    description: 'Get all progress',
  })
  @ApiResponse({ status: 200, type: [Progress] })
  @Get()
  findAll() {
    return this.progressService.findAll();
  }

  @ApiOperation({
    summary: 'Get progress by id',
    description: 'Get progress by id',
  })
  @ApiResponse({ status: 200, type: Progress })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.progressService.findOne(+id);
  }

  @ApiOperation({
    summary: 'Update progress',
    description: 'Update progress',
  })
  @ApiResponse({ status: 200, type: Progress })
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateProgressDto: UpdateProgressDto,
  ) {
    return this.progressService.update(+id, updateProgressDto);
  }

  @ApiOperation({
    summary: 'Delete progress',
    description: 'Delete progress',
  })
  @ApiResponse({ status: 200, type: Progress })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.progressService.remove(+id);
  }
}
