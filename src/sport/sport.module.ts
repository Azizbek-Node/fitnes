import { forwardRef, Module } from '@nestjs/common';
import { SportService } from './sport.service';
import { SportController } from './sport.controller';
import { SequelizeModule } from '@nestjs/sequelize';
import Sportinhall from '../sport-hall/models/sportinhall.model';
import Sport from './models/sport.model';
import { SportHallModule } from '../sport-hall/sport-hall.module';
import Booking from '../bookings/models/booking.model';
import Client from '../client/models/client.model';

@Module({
  imports: [
    SequelizeModule.forFeature([Sport, Sportinhall, Booking, Client]),
    forwardRef(() => SportHallModule),
  ],
  controllers: [SportController],
  exports: [SportService],
  providers: [SportService],
})
export class SportModule {}
