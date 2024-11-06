import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateClientDto } from './dto/create-client.dto';
import { UpdateClientDto } from './dto/update-client.dto';
import Client from './models/client.model';
import { InjectModel } from '@nestjs/sequelize';
import Abonement from '../abonement/models/abonement.model';
import Notification from '../notifications/models/notification.model';

@Injectable()
export class ClientService {
  constructor(
    @InjectModel(Client) private clientModel: typeof Client,
    @InjectModel(Abonement) private abonementModel: typeof Abonement,
    @InjectModel(Notification) private notificationModel: typeof Notification,
  ) {}

  async create(createClientDto: CreateClientDto) {
    const client = new Client(createClientDto);
    await client.save();

    if (createClientDto.abonementId) {
      const abonement = await this.abonementModel.findByPk(createClientDto.abonementId);
      await client.$set('abonement', abonement);
    }

    if (createClientDto.notificationId) {
      const notification = await this.notificationModel.findByPk(createClientDto.notificationId);
      await client.$set('notification', notification);
    }

    return client;
  }

  async findByEmail(email: string) {
    const client = await this.clientModel.findOne({ where: { email } });
    return client;
  }

  async findAll() {
    const clients = await this.clientModel.findAll({
      include: { all: true },
    });
    return clients;
  }

  async findOne(id: number) {
    const client = await this.clientModel.findByPk(id, {
      include: { all: true },
    });
    return client;
  }

  async update(id: number, updateClientDto: UpdateClientDto) {
    const client = await this.clientModel.findByPk(id);
    if (!client) {
      throw new NotFoundException('Client not found');
    }
    await client.update(updateClientDto);
    return client;
  }

  async remove(id: number) {
    const client = await this.clientModel.findByPk(id);
    if (!client) {
      throw new NotFoundException('Client not found');
    }
    await client.destroy();
    return client;
  }
}
