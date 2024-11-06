import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AdminModule } from '../admin/admin.module';
import { JwtModule } from '@nestjs/jwt';
import { SequelizeModule } from '@nestjs/sequelize';
import Admin from '../admin/models/admin.model';
import Client from '../client/models/client.model';
import { ClientService } from '../client/client.service';
import { ClientModule } from '../client/client.module';
import { MailModule } from '../mail/mail.module';
import Abonement from '../abonement/models/abonement.model';
import Notification from '../notifications/models/notification.model';

@Module({
  imports: [
    JwtModule.register({}),
    AdminModule,
    SequelizeModule.forFeature([Admin, Client, Abonement, Notification]),
    ClientModule,
    MailModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, ClientService],
})
export class AuthModule {}
