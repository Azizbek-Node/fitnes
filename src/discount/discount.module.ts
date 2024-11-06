import { Module } from '@nestjs/common';
import { DiscountService } from './discount.service';
import { DiscountController } from './discount.controller';
import Discount from './models/discount.model';
import { SequelizeModule } from '@nestjs/sequelize';
import { JwtModule, JwtService } from '@nestjs/jwt';
@Module({
  imports: [SequelizeModule.forFeature([Discount]), JwtModule.register({})],
  controllers: [DiscountController],
  providers: [DiscountService, JwtService],
})
export class DiscountModule {}
