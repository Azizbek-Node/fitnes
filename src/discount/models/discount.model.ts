import { ApiProperty } from '@nestjs/swagger';
import { Column, DataType, Model, Table } from 'sequelize-typescript';

interface IDiscount {
  amount: number;
  description: number;
}

@Table({ tableName: 'discounts', timestamps: false })
export class Discount extends Model<Discount, IDiscount> {
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
    example: 10,
    description: 'Discount amount',
  })
  @Column({
    type: DataType.INTEGER,
  })
  amount: number;

  @ApiProperty({
    example: '10% discount',
    description: 'Discount description',
  })
  @Column({
    type: DataType.INTEGER,
  })
  description: number;
}

export default Discount;
