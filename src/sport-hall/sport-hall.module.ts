import { forwardRef, Module } from '@nestjs/common';
import { SportHallService } from './sport-hall.service';
import { SportHallController } from './sport-hall.controller';
import { SportHall } from './models/sport-hall.model';
import { SequelizeModule } from '@nestjs/sequelize';
import Sportinhall from './models/sportinhall.model';
import Sport from '../sport/models/sport.model';
import Notification from '../notifications/models/notification.model';
import { SportModule } from '../sport/sport.module';
import { SportHallReviewModule } from '../sport-hall_review/sport-hall_review.module';
import Booking from '../bookings/models/booking.model';
import Trainer from '../trainers/models/trainer.model';

@Module({
  imports: [
    SequelizeModule.forFeature([
      SportHall,
      Sportinhall,
      Sport,
      Notification,
      Booking,
      Trainer,
    ]),
    forwardRef(() => SportModule),
    forwardRef(() => SportHallReviewModule),
  ],
  controllers: [SportHallController],
  exports: [SportHallService],
  providers: [SportHallService],
})
export class SportHallModule {}
