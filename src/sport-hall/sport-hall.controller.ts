import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { SportHallService } from './sport-hall.service';
import { CreateSportHallDto } from './dto/create-sport-hall.dto';
import { UpdateSportHallDto } from './dto/update-sport-hall.dto';
import { AddRemoveSportinhallDto } from './dto/add-remove-sportinhall.dto';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
@ApiTags('Sport Hall')
@Controller('sport-hall')
export class SportHallController {
  constructor(private readonly sportHallService: SportHallService) {}

  @ApiOperation({
    summary: 'Create sport hall',
    description: 'Create sport hall',
  })
  @Post()
  create(@Body() createSportHallDto: CreateSportHallDto) {
    return this.sportHallService.create(createSportHallDto);
  }

  @ApiOperation({
    summary: 'Get all sport halls',
    description: 'Get all sport halls',
  })
  @Get()
  findAll() {
    return this.sportHallService.findAll();
  }

  @ApiOperation({
    summary: 'Get sport hall by id',
    description: 'Get sport hall by id',
  })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.sportHallService.findOne(+id);
  }

  @ApiOperation({
    summary: 'Update sport hall',
    description: 'Update sport hall',
  })
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateSportHallDto: UpdateSportHallDto,
  ) {
    return this.sportHallService.update(+id, updateSportHallDto);
  }

  @ApiOperation({
    summary: 'Delete sport hall',
    description: 'Delete sport hall',
  })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.sportHallService.remove(+id);
  }

  @ApiOperation({
    summary: 'Add sport to sport hall',
    description: 'Add sport to sport hall',
  })
  @Post('sportinhall')
  addSportinhall(@Body() addRemoveSportinhallDto: AddRemoveSportinhallDto) {
    return this.sportHallService.addSportinhall(addRemoveSportinhallDto);
  }

  @ApiOperation({
    summary: 'Remove sport from sport hall',
    description: 'Remove sport from sport hall',
  })
  @Delete('sportinhall')
  removeSportinhall(@Body() addRemoveSportinhallDto: AddRemoveSportinhallDto) {
    return this.sportHallService.removeSportinhall(addRemoveSportinhallDto);
  }
}
