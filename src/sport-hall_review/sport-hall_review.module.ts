import { Module } from '@nestjs/common';
import { SportHallReviewService } from './sport-hall_review.service';
import { SportHallReviewController } from './sport-hall_review.controller';
import { SportHallReview } from './models/sport-hall_review.model';
import { SequelizeModule } from '@nestjs/sequelize';
import Client from '../client/models/client.model';
import SportHall from '../sport-hall/models/sport-hall.model';
import { SportHallService } from '../sport-hall/sport-hall.service';
import { ClientService } from '../client/client.service';
import Sport from '../sport/models/sport.model';
import Abonement from '../abonement/models/abonement.model';
import Notification from '../notifications/models/notification.model';
import Booking from '../bookings/models/booking.model';

@Module({
  imports: [
    SequelizeModule.forFeature([
      SportHallReview,
      Client,
      SportHall,
      Sport,
      Abonement,
      Notification,
      Booking,
    ]),
  ],
  controllers: [SportHallReviewController],
  providers: [SportHallReviewService, ClientService, SportHallService],
  exports: [SportHallReviewService],
})
export class SportHallReviewModule {}
