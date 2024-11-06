import { ApiProperty } from '@nestjs/swagger';
import { BelongsToMany, Column, DataType, Model, Table } from 'sequelize-typescript';
import { Sport } from '../../sport/models/sport.model';
import { Sportinhall } from './sportinhall.model';

interface ISportHall {
  name: string;
  phone: string;
  location: string;
  conditions: string;
  work_days: string;
  open_time: string;
  close_time: string;
  image: string;
}

@Table({ tableName: 'sport_halls', timestamps: false })
export class SportHall extends Model<SportHall, ISportHall> {
  @ApiProperty({
    example: 1,
    description: 'Unikal id',
  })
  @Column({
    type: DataType.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  })
  id: number;

  @ApiProperty({
    example: 'Buka',
    description: 'Sport zal nomi',
  })
  @Column({
    type: DataType.STRING,
  })
  name: string;

  @ApiProperty({
    example: '+998901234567',
    description: 'Sport zal telefon raqami',
  })
  @Column({ type: DataType.STRING })
  phone: string;

  @ApiProperty({
    example: 'Toshkent',
    description: 'Sport zal manzili',
  })
  @Column({ type: DataType.STRING })
  location: string;

  @ApiProperty({
    example: 'Yoshlar uchun',
    description: 'Sport zal sharoitlari',
  })
  @Column({ type: DataType.STRING })
  conditions: string;

  @ApiProperty({
    example: 'Dushanba-Juma',
    description: 'Sport zal ish kunlari',
  })
  @Column({ type: DataType.STRING })
  work_days: string;

  @ApiProperty({
    example: '10:00',
    description: 'Sport zal ochiq vaqt',
  })
  @Column({ type: DataType.STRING })
  open_time: string;

  @ApiProperty({
    example: '22:00',
    description: 'Sport zal yopiladigan vaqt',
  })
  @Column({ type: DataType.STRING })
  close_time: string;

  @ApiProperty({
    example: 'image.png',
    description: 'Sport zal rasmi',
  })
  @Column({ type: DataType.STRING })
  image: string;

  @ApiProperty({
    example: 1,
    description: 'Sport zal like',
  })
  @Column({
    type: DataType.INTEGER,
    defaultValue: 0,
  })
  likes: number;

  @BelongsToMany(() => Sport, () => Sportinhall)
  sports: Sport[];
}

export default SportHall;
