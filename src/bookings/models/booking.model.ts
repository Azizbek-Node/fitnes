import { ApiProperty } from '@nestjs/swagger';
import { Table, Model, PrimaryKey, DataType, Column, ForeignKey, BelongsTo } from 'sequelize-typescript';
import { SportHall } from '../../sport-hall/models/sport-hall.model';
import { Client } from '../../client/models/client.model';
import Sport from '../../sport/models/sport.model';

interface IBooking {
  sportId: number;
  clientId: number;
  date: string;
  isBooked: boolean;
}

@Table({ tableName: 'bookings', timestamps: false })
export class Booking extends Model<Booking, IBooking> {
  @ApiProperty({
    example: 1,
    description: 'Unikal id',
  })
  @PrimaryKey
  @Column({
    type: DataType.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  })
  id: number;

  @ApiProperty({
    example: true,
    description: 'Status',
  })
  @Column({ type: DataType.BOOLEAN })
  isBooked: boolean;

  @ApiProperty({
    example: '2024-01-01',
    description: 'Date',
  })
  @Column({
    type: DataType.STRING,
  })
  date: string;

  @ForeignKey(() => Sport)
  @Column({
    type: DataType.INTEGER,
  })
  sportId: number;

  @ForeignKey(() => Client)
  @Column({
    type: DataType.INTEGER,
  })
  clientId: number;

  @BelongsTo(() => Sport)
  sport: Sport;

  @BelongsTo(() => Client)
  client: Client;
}

export default Booking;
