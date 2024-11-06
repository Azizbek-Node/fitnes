import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { SequelizeModule } from '@nestjs/sequelize';
import { AuthModule } from './auth/auth.module';
import { SportHallModule } from './sport-hall/sport-hall.module';
import { SportModule } from './sport/sport.module';
import { AdminModule } from './admin/admin.module';
import { LimitedModule } from './limited/limited.module';
import { NotificationsModule } from './notifications/notifications.module';
import { DiscountModule } from './discount/discount.module';
import { AbonementModule } from './abonement/abonement.module';
import { PaymentModule } from './payment/payment.module';
import { ClientModule } from './client/client.module';
import { BookingsModule } from './bookings/bookings.module';
import { SportHallReviewModule } from './sport-hall_review/sport-hall_review.module';
import { TrainersModule } from './trainers/trainers.module';
import { FeedbackModule } from './feedback/feedback.module';
import { ProgressModule } from './progress/progress.module';
@Module({
  imports: [
    ConfigModule.forRoot({ envFilePath: '.env', isGlobal: true }),
    SequelizeModule.forRoot({
      dialect: 'postgres',
      host: process.env.POSTGRES_HOST,
      port: Number(process.env.PG_PORT),
      username: process.env.PG_USERNAME,
      password: process.env.PG_PASSWORD,
      database: process.env.PG_DATABASE,
      models: [__dirname + '/**/*.model{.ts,.js}'],
      autoLoadModels: true,
      logging: true,
    }),
    AdminModule,
    AuthModule,
    SportHallModule,
    SportModule,
    LimitedModule,
    NotificationsModule,
    DiscountModule,
    AbonementModule,
    PaymentModule,
    ClientModule,
    BookingsModule,
    SportHallReviewModule,
    TrainersModule,
    FeedbackModule,
    ProgressModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
