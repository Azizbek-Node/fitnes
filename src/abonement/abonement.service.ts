import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateAbonementDto } from './dto/create-abonement.dto';
import { UpdateAbonementDto } from './dto/update-abonement.dto';
import { InjectModel } from '@nestjs/sequelize';
import Abonement from './models/abonement.model';
import { DiscountService } from '../discount/discount.service';

@Injectable()
export class AbonementService {
  constructor(
    @InjectModel(Abonement) private abonementModel: typeof Abonement,
    private readonly discountService: DiscountService,
  ) {}

  async create(createAbonementDto: CreateAbonementDto) {
    const discount = await this.discountService.findOne(
      createAbonementDto.discountId,
    );
    if (discount.amount <= 0) {
      throw new BadRequestException('Chegirma tugagan kerak');
    }
    const originalPrice = createAbonementDto.price;
    const discountPrice = (originalPrice * discount.description) / 100;
    const finalPrice = originalPrice - discountPrice;
    const startDate = new Date();
    const endDate = new Date(startDate);
    endDate.setMonth(endDate.getMonth() + createAbonementDto.duration);
    const abonement = await this.abonementModel.create({
      ...createAbonementDto,
      startDate,
      endDate,
    });
    await this.discountService.updateAmount(discount.id, discount.amount - 1);
    return {
      abonement,
      discountPrice,
      finalPrice,
    };
  }

  async findAll() {
    const setPrice = async (abonements: Abonement[]) => {
      for (const abonement of abonements) {
        const discount = await this.discountService.findOne(
          abonement.discountId,
        );
        abonement.price =
          (abonement.price * (100 - discount.description)) / 100;
      }
    };
    const abonements = await this.abonementModel.findAll({
      include: [{ all: true }],
    });
    await setPrice(abonements);
    return abonements;
  }

  async findOne(id: number) {
    const abonement = await this.abonementModel.findByPk(id, {
      include: [{ all: true }],
    });
    const discount = await this.discountService.findOne(abonement.discountId);
    abonement.price = (abonement.price * (100 - discount.description)) / 100;
    return abonement;
  }

  async update(id: number, updateAbonementDto: UpdateAbonementDto) {
    return await this.abonementModel.update(updateAbonementDto, {
      where: { id },
    });
  }

  async remove(id: number) {
    return await this.abonementModel.destroy({ where: { id } });
  }
}
