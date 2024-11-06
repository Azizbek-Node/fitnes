import { Module } from '@nestjs/common';
import { AbonementService } from './abonement.service';
import { AbonementController } from './abonement.controller';
import Abonement from './models/abonement.model';
import { Discount } from '../discount/models/discount.model';
import { SequelizeModule } from '@nestjs/sequelize';
import { DiscountService } from '../discount/discount.service';
import { SportHallReview } from '../sport-hall_review/models/sport-hall_review.model';
import Client from '../client/models/client.model';
import { JwtModule, JwtService } from '@nestjs/jwt';
@Module({
  imports: [
    SequelizeModule.forFeature([Abonement, Discount, SportHallReview, Client]),
    JwtModule.register({}),
  ],
  controllers: [AbonementController],
  providers: [AbonementService, DiscountService, JwtService],
})
export class AbonementModule {}
