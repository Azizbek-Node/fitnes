import { ApiProperty } from '@nestjs/swagger';
import { Column, DataType, ForeignKey, Model, Table } from 'sequelize-typescript';
import Abonement from '../../abonement/models/abonement.model';

interface IPayment {
  abonementId: number;
  status: string;
  method: string;
}

@Table({ tableName: 'payments', timestamps: false })
export class Payment extends Model<Payment, IPayment> {
  @ApiProperty({
    example: 1,
    description: 'Unikal ID',
  })
  @Column({
    type: DataType.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  })
  id: number;

  @ApiProperty({
    example: 'paid',
    description: 'Tolanadigan status',
  })
  @Column({
    type: DataType.STRING,
  })
  status: string;

  @ApiProperty({
    example: 'card',
    description: 'Tolanadigan usul',
  })
  @Column({
    type: DataType.STRING,
  })
  method: string;

  @ForeignKey(() => Abonement)
  @ApiProperty({
    example: 1,
    description: 'Abonement ID',
  })
  @Column({
    type: DataType.INTEGER,
  })
  abonementId: number;
}

export default Payment;
