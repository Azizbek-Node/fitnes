import { DataType, Model, Table, Column, ForeignKey } from 'sequelize-typescript';
import { Sport } from '../../sport/models/sport.model';
import { SportHall } from './sport-hall.model';

interface ISportinhall {
  sportId: number;
  sportHallId: number;
}

@Table({ tableName: 'sportinhall', timestamps: false })
export class Sportinhall extends Model<Sportinhall, ISportinhall> {
  @ForeignKey(() => Sport)
  @Column({ type: DataType.INTEGER })
  sportId: number;

  @ForeignKey(() => SportHall)
  @Column({ type: DataType.INTEGER })
  sportHallId: number;
}

export default Sportinhall; 
