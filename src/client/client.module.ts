import { forwardRef, Module } from '@nestjs/common';
import { ClientService } from './client.service';
import { ClientController } from './client.controller';
import { SequelizeModule } from '@nestjs/sequelize';
import Client from './models/client.model';
import Abonement from '../abonement/models/abonement.model';
import Notification from '../notifications/models/notification.model';
import Sport from '../sport/models/sport.model';
import Booking from '../bookings/models/booking.model';
import { SportHallReview } from '../sport-hall_review/models/sport-hall_review.model';
import { SportHallReviewModule } from '../sport-hall_review/sport-hall_review.module';
import Feedback from '../feedback/models/feedback.model';
import { FeedbackModule } from '../feedback/feedback.module';
import { JwtModule, JwtService } from '@nestjs/jwt';
import Progress from '../progress/models/progress.model';

@Module({
  imports: [
    SequelizeModule.forFeature([
      Client,
      Abonement,
      Notification,
      Sport,
      Booking,
      SportHallReview,
      Feedback,
      Progress,
    ]),
    JwtModule.register({}),
    forwardRef(() => SportHallReviewModule),
    FeedbackModule,
  ],
  controllers: [ClientController],
  providers: [ClientService, JwtService],
  exports: [ClientService],
})
export class ClientModule {}
