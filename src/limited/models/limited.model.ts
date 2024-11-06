import { ApiProperty } from '@nestjs/swagger';
import {
  Table,
  Column,
  Model,
  DataType,
  ForeignKey,
  BelongsTo,
} from 'sequelize-typescript';
import SportHall from '../../sport-hall/models/sport-hall.model';

interface ILimited {
  sportHallId: number;
  date: Date;
  startTime: Date;
  endTime: Date;
}

@Table({ tableName: 'limited', timestamps: false })
export class Limited extends Model<Limited, ILimited> {
  @ApiProperty({
    example: 1,
    description: 'Unique id',
  })
  @Column({
    type: DataType.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  })
  id: number;

  @ApiProperty({
    example: '2024-01-01',
    description: 'Date',
  })
  @Column({
    type: DataType.DATE,
  })
  date: Date;

  @ApiProperty({
    example: '10:00',
    description: 'Start time',
  })
  @Column({
    type: DataType.TIME,
  })
  startTime: string;

  @ApiProperty({
    example: '14:00',
    description: 'End time',
  })
  @Column({
    type: DataType.TIME,
  })
  endTime: string;

  @ApiProperty({
    example: 1,
    description: 'Sport hall id',
  })
  @ForeignKey(() => SportHall)
  @Column({
    type: DataType.INTEGER,
  })
  sportHallId: number;

  @BelongsTo(() => SportHall)
  sportHall: SportHall;
}

export default Limited;
