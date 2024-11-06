import { Module } from '@nestjs/common';
import { LimitedService } from './limited.service';
import { LimitedController } from './limited.controller';
import { Limited } from './models/limited.model';
import { SequelizeModule } from '@nestjs/sequelize';
import SportHall from '../sport-hall/models/sport-hall.model';
import { JwtModule, JwtService } from '@nestjs/jwt';
@Module({
  imports: [
    SequelizeModule.forFeature([Limited, SportHall]),
    JwtModule.register({}),
  ],
  controllers: [LimitedController],
  providers: [LimitedService, JwtService],
})
export class LimitedModule {}
