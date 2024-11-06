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
import { DiscountService } from './discount.service';
import { CreateDiscountDto } from './dto/create-discount.dto';
import { UpdateDiscountDto } from './dto/update-discount.dto';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AdminIsCreatorGuard } from '../common/guards';

@ApiTags('Discount')
@Controller('discount')
export class DiscountController {
  constructor(private readonly discountService: DiscountService) {}

  @UseGuards(AdminIsCreatorGuard)
  @ApiOperation({
    summary: 'Create discount',
    description: 'Create discount',
  })
  @Post()
  create(@Body() createDiscountDto: CreateDiscountDto) {
    return this.discountService.create(createDiscountDto);
  }

  @ApiOperation({
    summary: 'Get all discounts',
    description: 'Get all discounts',
  })
  @Get()
  findAll() {
    return this.discountService.findAll();
  }

  @ApiOperation({
    summary: 'Get discount by id',
    description: 'Get discount by id',
  })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.discountService.findOne(+id);
  }

  @ApiOperation({
    summary: 'Update discount',
    description: 'Update discount',
  })
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateDiscountDto: UpdateDiscountDto,
  ) {
    return this.discountService.update(+id, updateDiscountDto);
  }

  @ApiOperation({
    summary: 'Delete discount',
    description: 'Delete discount',
  })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.discountService.remove(+id);
  }
}
