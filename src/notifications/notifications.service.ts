import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateNotificationDto } from './dto/create-notification.dto';
import { UpdateNotificationDto } from './dto/update-notification.dto';
import { InjectModel } from '@nestjs/sequelize';
import { Notification } from './models/notification.model';
import SportHall from '../sport-hall/models/sport-hall.model';

@Injectable()
export class NotificationsService {
  constructor(
    @InjectModel(Notification) private notificationModel: typeof Notification,
    @InjectModel(SportHall) private sportHallModel: typeof SportHall,
  ) {}
  async create(createNotificationDto: CreateNotificationDto) {
    const sportHall = await this.sportHallModel.findByPk(
      createNotificationDto.sportHallId,
    );
    if (!sportHall) {
      throw new NotFoundException('Sport hall not found');
    }
    const notification = await this.notificationModel.create(
      createNotificationDto,
    );
    await sportHall.$add('notifications', notification.id);
    return notification;
  }

  findAll() {
    return this.notificationModel.findAll({ include: { all: true } });
  }

  findOne(id: number) {
    return this.notificationModel.findByPk(id, { include: { all: true } });
  }

  update(id: number, updateNotificationDto: UpdateNotificationDto) {
    return this.notificationModel.update(updateNotificationDto, {
      where: { id },
    });
  }

  remove(id: number) {
    return this.notificationModel.destroy({ where: { id } });
  }
}
