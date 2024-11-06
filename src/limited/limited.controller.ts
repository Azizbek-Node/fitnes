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
import { LimitedService } from './limited.service';
import { CreateLimitedDto } from './dto/create-limited.dto';
import { UpdateLimitedDto } from './dto/update-limited.dto';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AdminGuard } from '../common/guards';

@ApiTags('Limited')
@UseGuards(AdminGuard)
@Controller('limited')
export class LimitedController {
  constructor(private readonly limitedService: LimitedService) {}

  @ApiOperation({
    summary: 'Create limited',
    description: 'Create limited',
  })
  @Post()
  create(@Body() createLimitedDto: CreateLimitedDto) {
    return this.limitedService.create(createLimitedDto);
  }

  @ApiOperation({
    summary: 'Get all limited',
    description: 'Get all limited',
  })
  @Get()
  findAll() {
    return this.limitedService.findAll();
  }

  @ApiOperation({
    summary: 'Get limited by id',
    description: 'Get limited by id',
  })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.limitedService.findOne(+id);
  }

  @ApiOperation({
    summary: 'Update limited',
    description: 'Update limited',
  })
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateLimitedDto: UpdateLimitedDto) {
    return this.limitedService.update(+id, updateLimitedDto);
  }

  @ApiOperation({
    summary: 'Delete limited',
    description: 'Delete limited',
  })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.limitedService.remove(+id);
  }
}
