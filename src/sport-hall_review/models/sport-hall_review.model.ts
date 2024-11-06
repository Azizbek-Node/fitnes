import {
  BelongsTo,
  Column,
  ForeignKey,
  Model,
  Table,
  DataType,
} from 'sequelize-typescript';
import Client from '../../client/models/client.model';
import SportHall from '../../sport-hall/models/sport-hall.model';
import { ApiProperty } from '@nestjs/swagger';

interface ISportHallReview {
  clientId: number;
  sportHallId: number;
  comment: string;
  likes: number;
}

@Table({ tableName: 'sport_hall_review', timestamps: false })
export class SportHallReview extends Model<SportHallReview, ISportHallReview> {
  @ApiProperty({
    example: 1,
    description: 'unikal ID',
  })
  @Column({
    type: DataType.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  })
  id: number;

  @ApiProperty({
    example: 1,
    description: 'Client ID',
  })
  @ForeignKey(() => Client)
  @Column({ type: DataType.INTEGER })
  clientId: number;

  @ApiProperty({
    example: 1,
    description: 'Sport Hall ID',
  })
  @ForeignKey(() => SportHall)
  @Column({
    type: DataType.INTEGER,
    allowNull: true,
  })
  sportHallId: number;

  @ApiProperty({
    example: 'Good',
    description: 'Comment',
  })
  @Column({
    type: DataType.STRING,
    allowNull: true,
  })
  comment: string;

  @ApiProperty({
    example: 1,
    description: 'Likes',
  })
  @Column({
    type: DataType.INTEGER,
    defaultValue: 0,
  })
  likes: number;

  @BelongsTo(() => Client)
  client: Client;

  @BelongsTo(() => SportHall)
  sportHall: SportHall;
}

export default SportHallReview;
