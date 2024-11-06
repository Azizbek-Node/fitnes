import { ApiProperty } from '@nestjs/swagger';
import { BelongsTo, Column, DataType, ForeignKey, HasMany, Model, Table } from 'sequelize-typescript';
import Notification from '../../notifications/models/notification.model';
import Abonement from '../../abonement/models/abonement.model';

interface IClient {
  abonementId: number;
  notificationId: number;
  fname: string;
  lname: string;
  email: string;
  password: string;
  phone: string;
  gender: string;
  age: number;
}

@Table({ tableName: 'clients', timestamps: false })
export class Client extends Model<Client, IClient> {
  @Column({
    type: DataType.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  })
  id: number;

  @ApiProperty({
    example: 'Azizbek',
    description: 'Client first name',
  })
  @Column({
    type: DataType.STRING,
  })
  fname: string;

  @ApiProperty({
    example: 'To`raxonov',
    description: 'Client last name',
  })
  @Column({
    type: DataType.STRING,
  })
  lname: string;

  @ApiProperty({
    example: 'azizbek@gmail.com',
    description: 'Client email',
  })
  @Column({
    type: DataType.STRING,
  })
  email: string;

  @ApiProperty({
    example: '1234567890',
    description: 'Client password',
  })
  @Column({
    type: DataType.STRING,
  })
  password: string;

  @ApiProperty({
    example: '+998901234567',
    description: 'Client phone number',
  })
  @Column({
    type: DataType.STRING,
  })
  phone: string;

  @ApiProperty({
    example: 'male',
    description: 'Client gender',
  })
  @Column({
    type: DataType.STRING,
  })
  gender: string;

  @ApiProperty({
    example: 20,
    description: 'Client age',
  })
  @Column({
    type: DataType.INTEGER,
  })
  age: number;

  @ForeignKey(() => Abonement)
  @ApiProperty({
    example: 1,
    description: 'Abonement ID',
  })
  @Column({
    type: DataType.INTEGER,
  })
  abonementId: number;

  @ForeignKey(() => Notification)
  @ApiProperty({
    example: 1,
    description: 'Notification ID',
  })
  @Column({
    type: DataType.INTEGER,
  })
  notificationId: number;

  @Column({
    type: DataType.STRING,
  })
  activation_link: string;

  @Column({
    type: DataType.STRING,
  })
  refresh_token: string;

  @Column({
    type: DataType.BOOLEAN,
    defaultValue: false,
  })
  is_active: boolean;

  @BelongsTo(() => Abonement)
  abonement: Abonement;

  @BelongsTo(() => Notification)
  notification: Notification;
}

export default Client;