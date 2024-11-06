import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { AbonementService } from './abonement.service';
import { CreateAbonementDto } from './dto/create-abonement.dto';
import { UpdateAbonementDto } from './dto/update-abonement.dto';
import { ApiOperation, ApiTags } from '@nestjs/swagger';

@ApiTags('Abonement')
@Controller('abonement')
export class AbonementController {
  constructor(private readonly abonementService: AbonementService) {}

  @ApiOperation({
    summary: 'Create abonement',
    description: 'Create abonement',
  })
  @Post()
  create(@Body() createAbonementDto: CreateAbonementDto) {
    return this.abonementService.create(createAbonementDto);
  }

  @ApiOperation({
    summary: 'Get all abonements',
    description: 'Get all abonements',
  })
  @Get()
  findAll() {
    return this.abonementService.findAll();
  }

  @ApiOperation({
    summary: 'Get abonement by id',
    description: 'Get abonement by id',
  })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.abonementService.findOne(+id);
  }

  @ApiOperation({
    summary: 'Update abonement',
    description: 'Update abonement',
  })
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateAbonementDto: UpdateAbonementDto,
  ) {
    return this.abonementService.update(+id, updateAbonementDto);
  }

  @ApiOperation({
    summary: 'Delete abonement',
    description: 'Delete abonement',
  })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.abonementService.remove(+id);
  }
}
