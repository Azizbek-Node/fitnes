import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateDiscountDto } from './dto/create-discount.dto';
import { UpdateDiscountDto } from './dto/update-discount.dto';
import Discount from './models/discount.model';
import { InjectModel } from '@nestjs/sequelize';

@Injectable()
export class DiscountService {
  constructor(@InjectModel(Discount) private discountModel: typeof Discount) {}

  async create(createDiscountDto: CreateDiscountDto) {
    return await this.discountModel.create(createDiscountDto);
  }

  async updateAmount(id: number, newAmount: number) {
    const discount = await this.discountModel.findByPk(id);
    if (!discount) {
      throw new NotFoundException('Discount not found');
    }
    discount.amount = newAmount;
    await discount.save();
    return discount;
  }

  async findAll() {
    return await this.discountModel.findAll({ include: [{ all: true }] });
  }

  async findOne(id: number) {
    return await this.discountModel.findByPk(id, { include: [{ all: true }] });
  }

  async update(id: number, updateDiscountDto: UpdateDiscountDto) {
    return await this.discountModel.update(updateDiscountDto, {
      where: { id },
    });
  }

  async remove(id: number) {
    return await this.discountModel.destroy({ where: { id } });
  }
}
