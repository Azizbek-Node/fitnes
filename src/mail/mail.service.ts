import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import Client from '../client/models/client.model';

@Injectable()
export class MailService {
  constructor(private mailerService: MailerService) {}

  async sendMail(client: Client) {
    const url = `${process.env.API_URL}:${process.env.API_PORT}/api/auth/activate/${client.activation_link}`;
    console.log(url);
    await this.mailerService.sendMail({
      to: client.email,
      subject: 'Fitnes appga hush kelibsiz',
      template: './confirm',
      context: {
        lname: client.lname,
        url,
      },
    });
  }
}
