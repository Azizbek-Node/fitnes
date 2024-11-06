import { Module } from '@nestjs/common';
import { FeedbackService } from './feedback.service';
import { FeedbackController } from './feedback.controller';
import { Feedback } from './models/feedback.model';
import { SequelizeModule } from '@nestjs/sequelize';
import Trainer from '../trainers/models/trainer.model';
import Client from '../client/models/client.model';
import { JwtModule, JwtService } from '@nestjs/jwt';
@Module({
  imports: [
    SequelizeModule.forFeature([Feedback, Trainer, Client]),
    JwtModule.register({}),
  ],
  controllers: [FeedbackController],
  providers: [FeedbackService, JwtService],
})
export class FeedbackModule {}
