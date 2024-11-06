import { ApiProperty } from '@nestjs/swagger';
import {
  BelongsTo,
  Column,
  DataType,
  ForeignKey,
  Model,
  Table,
} from 'sequelize-typescript';
import SportHall from '../../sport-hall/models/sport-hall.model';

interface ITrainer {
  sportHallId: number;
  name: string;
  email: string;
  password: string;
  phone: string;
  experience: string;
  gender: string;
}

@Table({ tableName: 'trainers', timestamps: false })
export class Trainer extends Model<Trainer, ITrainer> {
  @ApiProperty({
    example: 1,
    description: 'Unique identifier',
  })
  @Column({
    type: DataType.INTEGER,
    unique: true,
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
    example: 'John Doe',
    description: 'Trainer name',
  })
  @Column({
    type: DataType.STRING,
  })
  name: string;

  @ApiProperty({
    example: 'abbosturgunov@gmail.com',
    description: 'Trainer email',
  })
  @Column({
    type: DataType.STRING,
  })
  email: string;

  @ApiProperty({
    example: '123456',
    description: 'Password',
  })
  @Column({
    type: DataType.STRING,
  })
  password: string;

  @ApiProperty({
    example: '+998991234567',
    description: 'Phone',
  })
  @Column({
    type: DataType.STRING,
  })
  phone: string;

  @ApiProperty({
    example: '1 year',
    description: 'Trainer experience',
  })
  @Column({
    type: DataType.STRING,
  })
  experience: string;

  @BelongsTo(() => SportHall)
  sportHall: SportHall;
}

export default Trainer;
