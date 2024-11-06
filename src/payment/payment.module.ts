import { Module } from '@nestjs/common';
import { PaymentService } from './payment.service';
import { PaymentController } from './payment.controller';
import { Abonement } from '../abonement/models/abonement.model';
import { SequelizeModule } from '@nestjs/sequelize';
import Payment from './models/payment.model';
import { JwtModule, JwtService } from '@nestjs/jwt';
@Module({
  imports: [
    SequelizeModule.forFeature([Payment, Abonement]),
    JwtModule.register({}),
  ],
  controllers: [PaymentController],
  providers: [PaymentService, JwtService],
})
export class PaymentModule {}
