import {
  BelongsToMany,
  Column,
  DataType,
  Model,
  Table,
} from 'sequelize-typescript';

import { ApiProperty } from '@nestjs/swagger';
import { SportHall } from '../../sport-hall/models/sport-hall.model';
import { Sportinhall } from '../../sport-hall/models/sportinhall.model';

interface ISport {
  name: string;
}

@Table({ tableName: 'sports', timestamps: false })
export class Sport extends Model<Sport, ISport> {
  @ApiProperty({
    example: 1,
    description: 'Sport unikal id',
  })
  @Column({
    type: DataType.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  })
  id: number;

  @ApiProperty({
    example: 'Futbol',
    description: 'Sport nomi',
  })
  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  name: string;

  @BelongsToMany(() => SportHall, () => Sportinhall)
  sportHalls: SportHall[];
}

export default Sport;
