import { Module } from '@nestjs/common';
import { ProgressService } from './progress.service';
import { ProgressController } from './progress.controller';
import { Progress } from './models/progress.model';
import Client from '../client/models/client.model';
import { SequelizeModule } from '@nestjs/sequelize';

@Module({
  imports: [SequelizeModule.forFeature([Progress, Client])],
  controllers: [ProgressController],
  providers: [ProgressService],
})
export class ProgressModule {}
