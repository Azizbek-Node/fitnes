import { Module } from '@nestjs/common';
import { BookingsService } from './bookings.service';
import { BookingsController } from './bookings.controller';
import { Booking } from './models/booking.model';
import { Client } from '../client/models/client.model';
import { SequelizeModule } from '@nestjs/sequelize';
import Sport from '../sport/models/sport.model';
import { JwtModule, JwtService } from '@nestjs/jwt';

@Module({
  imports: [
    SequelizeModule.forFeature([Booking, Client, Sport]),
    JwtModule.register({}),
  ],
  controllers: [BookingsController],
  providers: [BookingsService, JwtService],
})
export class BookingsModule {}
