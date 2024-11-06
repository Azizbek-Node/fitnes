import { forwardRef, Module } from "@nestjs/common";
import { SportHallModule } from "../sport-hall/sport-hall.module";
import { SportModule } from "../sport/sport.module";
import { SequelizeModule } from "@nestjs/sequelize";
import Notification from "./models/notification.model";
import SportHall from "../sport-hall/models/sport-hall.model";
import { NotificationsController } from "./notifications.controller";
import { NotificationsService } from "./notifications.service";
import { SportHallService } from "../sport-hall/sport-hall.service";
import { SportService } from "../sport/sport.service";
import Sport from "../sport/models/sport.model";
import { JwtModule, JwtService } from '@nestjs/jwt';
@Module({
  imports: [
    forwardRef(() => SportHallModule),
    forwardRef(() => SportModule),
    SequelizeModule.forFeature([Notification, SportHall, Sport]),
    JwtModule.register({}),
  ],
  controllers: [NotificationsController],
  providers: [NotificationsService, SportHallService, SportService, JwtService],
  exports: [NotificationsService],
})
export class NotificationsModule {}
