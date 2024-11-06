import { ApiProperty } from '@nestjs/swagger';
import {
  BelongsTo,
  Column,
  DataType,
  ForeignKey,
  Model,
} from 'sequelize-typescript';

import { Table } from 'sequelize-typescript';
import Discount from '../../discount/models/discount.model';

interface IAbonement {
  discountId: number;
  duration: number;
  clientAmount: number;
  startDate: Date;
  endDate: Date;
  isActive: boolean;
  price: number;
}

@Table({ tableName: 'abonements', timestamps: false })
export class Abonement extends Model<Abonement, IAbonement> {
  @ApiProperty({
    example: 1,
    description: 'Unique id',
  })
  @Column({
    type: DataType.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  })
  id: number;

  @ApiProperty({
    example: 1,
    description: 'Abonement duration (month)',
  })
  @Column({
    type: DataType.INTEGER,
  })
  duration: number;

  @ApiProperty({
    example: 3,
    description: 'Abonement client amount',
  })
  @Column({
    type: DataType.INTEGER,
  })
  clientAmount: number;

  @ApiProperty({
    example: '2024-01-01',
    description: 'Abonement start date',
  })
  @Column({
    type: DataType.DATE,
  })
  startDate: Date;

  @ApiProperty({
    example: '2024-02-01',
    description: 'Abonement end date',
  })
  @Column({
    type: DataType.DATE,
  })
  endDate: Date;

  @ApiProperty({
    example: true,
    description: 'Abonement is active',
  })
  @Column({
    type: DataType.BOOLEAN,
  })
  isActive: boolean;

  @ApiProperty({
    example: 1000000,
    description: 'Abonement price',
  })
  @Column({
    type: DataType.INTEGER,
  })
  price: number;

  @ApiProperty({
    example: 1,
    description: 'Discount id',
  })
  @ForeignKey(() => Discount)
  @Column({
    type: DataType.INTEGER,
  })
  discountId: number;

  @BelongsTo(() => Discount)
  discount: Discount;
}

export default Abonement;
