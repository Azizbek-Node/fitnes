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
import { TrainersService } from './trainers.service';
import { CreateTrainerDto } from './dto/create-trainer.dto';
import { UpdateTrainerDto } from './dto/update-trainer.dto';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AdminGuard } from '../common/guards';

@ApiTags('Trainers')
@UseGuards(AdminGuard)
@Controller('trainers')
export class TrainersController {
  constructor(private readonly trainersService: TrainersService) {}

  @ApiOperation({
    summary: 'Create trainer',
    description: 'Create trainer with sport hall id',
  })
  @Post()
  create(@Body() createTrainerDto: CreateTrainerDto) {
    return this.trainersService.create(createTrainerDto);
  }

  @ApiOperation({
    summary: 'Get all trainers',
    description: 'Get all trainers with sport hall',
  })
  @Get()
  findAll() {
    return this.trainersService.findAll();
  }

  @ApiOperation({
    summary: 'Get trainer by id',
    description: 'Get trainer by id with sport hall',
  })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.trainersService.findOne(+id);
  }

  @ApiOperation({
    summary: 'Update trainer',
    description: 'Update trainer by id',
  })
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateTrainerDto: UpdateTrainerDto) {
    return this.trainersService.update(+id, updateTrainerDto);
  }

  @ApiOperation({
    summary: 'Delete trainer',
    description: 'Delete trainer by id',
  })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.trainersService.remove(+id);
  }
}
