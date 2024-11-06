import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { SportService } from './sport.service';
import { CreateSportDto } from './dto/create-sport.dto';
import { UpdateSportDto } from './dto/update-sport.dto';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Sport')
@Controller('sport')
export class SportController {
  constructor(private readonly sportService: SportService) {}

  @ApiOperation({
    summary: 'Sport yaratish',
    description: 'Sport yaratish',
  })
  @Post()
  create(@Body() createSportDto: CreateSportDto) {
    return this.sportService.create(createSportDto);
  }

  @ApiOperation({
    summary: 'Sportlar royhatini olish',
    description: 'Sportlar royhatini olish',
  })
  @Get()
  findAll() {
    return this.sportService.findAll();
  }

  @ApiOperation({
    summary: 'Sportni id boyicha olish',
    description: 'Sportni id boyicha olish',
  })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.sportService.findOne(+id);
  }

  @ApiOperation({
    summary: 'Sportni id boyicha update qilish',
    description: 'Sportni id boyicha update qilish',
  })
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateSportDto: UpdateSportDto) {
    return this.sportService.update(+id, updateSportDto);
  }

  @ApiOperation({
    summary: 'Sportni id boyicha ochirish',
    description: 'Sportni id boyicha ochirish',
  })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.sportService.remove(+id);
  }
}
