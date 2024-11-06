import {
  Column,
  DataType,
  ForeignKey,
  Model,
  Table,
  BelongsTo,
} from 'sequelize-typescript';
import SportHall from '../../sport-hall/models/sport-hall.model';
import { ApiProperty } from '@nestjs/swagger';

interface INotification {
  sportHallId: number;
  message: string;
}

@Table({ tableName: 'notifications', timestamps: false })
export class Notification extends Model<Notification, INotification> {
  @ApiProperty({
    example: 1,
    description: 'Notification id',
  })
  @Column({
    type: DataType.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  })
  id: number;

  @ApiProperty({
    example: 1,
    description: 'Sport hall id',
  })
  @ForeignKey(() => SportHall)
  @Column({
    type: DataType.INTEGER,
  })
  sportHallId: number;

  @ApiProperty({
    example: 'Hello',
    description: 'Message',
  })
  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  message: string;

  @BelongsTo(() => SportHall)
  sportHall: SportHall;
}

export default Notification;
