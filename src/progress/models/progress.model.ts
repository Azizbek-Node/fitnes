import { ApiProperty } from '@nestjs/swagger';
import {
  Table,
  Column,
  Model,
  DataType,
  BelongsTo,
  ForeignKey,
} from 'sequelize-typescript';
import Client from '../../client/models/client.model';

interface IProgress {
  clientId: number;
  weight: number;
  bodyFatPercentage: number;
  muscleMass: number;
  date: Date;
}

@Table({ tableName: 'progress', timestamps: false })
export class Progress extends Model<Progress, IProgress> {
  @ApiProperty({
    example: 1,
    description: 'Unique identifier',
  })
  @Column({
    type: DataType.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  })
  id: number;

  @ApiProperty({
    example: 1,
    description: 'Client id',
  })
  @ForeignKey(() => Client)
  @Column({
    type: DataType.INTEGER,
  })
  clientId: number;

  @ApiProperty({
    example: 60,
    description: 'Weight',
  })
  @Column({
    type: DataType.FLOAT,
  })
  weight: number;

  @ApiProperty({
    example: 14.5,
    description: 'Body fat percentage',
  })
  @Column({
    type: DataType.FLOAT,
  })
  bodyFatPercentage: number;

  @ApiProperty({
    example: 10,
    description: 'Muscle mass',
  })
  @Column({
    type: DataType.FLOAT,
  })
  muscleMass: number;

  @ApiProperty({
    example: '2024-01-01',
    description: 'Date',
  })
  @Column({
    type: DataType.DATE,
    defaultValue: new Date(),
  })
  date: Date;

  @BelongsTo(() => Client)
  client: Client;
}

export default Progress;
