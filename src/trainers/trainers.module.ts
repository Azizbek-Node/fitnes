import { Module } from '@nestjs/common';
import { TrainersService } from './trainers.service';
import { TrainersController } from './trainers.controller';
import { SportHallModule } from '../sport-hall/sport-hall.module';
import { SequelizeModule } from '@nestjs/sequelize';
import Trainer from './models/trainer.model';
import SportHall from '../sport-hall/models/sport-hall.model';
import { FeedbackModule } from '../feedback/feedback.module';
import Feedback from '../feedback/models/feedback.model';
import { JwtModule, JwtService } from '@nestjs/jwt';

@Module({
  imports: [
    SequelizeModule.forFeature([Trainer, SportHall, Feedback]),
    SportHallModule,
    FeedbackModule,
    JwtModule.register({}),
  ],
  controllers: [TrainersController],
  providers: [TrainersService, JwtService],
})
export class TrainersModule {}
