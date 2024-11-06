import { Injectable, NotFoundException } from '@nestjs/common';
import { CreatePaymentDto } from './dto/create-payment.dto';
import { UpdatePaymentDto } from './dto/update-payment.dto';
import { Payment } from './models/payment.model';
import { InjectModel } from '@nestjs/sequelize';
import Abonement from '../abonement/models/abonement.model';

@Injectable()
export class PaymentService {
  constructor(@InjectModel(Payment) private paymentModel: typeof Payment) {}

  async create(createPaymentDto: CreatePaymentDto) {
    const payment = await this.paymentModel.create(createPaymentDto);
    return payment;
  }

  async findAll() {
    return await this.paymentModel.findAll({ include: { all: true } });
  }

  async findOne(id: number) {
    return await this.paymentModel.findByPk(id, { include: { all: true } });
  }

  async update(id: number, updatePaymentDto: UpdatePaymentDto) {
    return await this.paymentModel.update(updatePaymentDto, {
      where: { id },
    });
  }

  async remove(id: number) {
    return await this.paymentModel.destroy({ where: { id } });
  }
}
