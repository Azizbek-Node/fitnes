import {
  BelongsTo,
  Column,
  ForeignKey,
  Model,
  Table,
  DataType,
} from 'sequelize-typescript';
import Trainer from '../../trainers/models/trainer.model';
import Client from '../../client/models/client.model';
import { ApiProperty } from '@nestjs/swagger';

interface IFeedback {
  trainerId: number;
  clientId: number;
  stars: number;
  comment: string;
}

@Table({ tableName: 'feedbacks', timestamps: false })
export class Feedback extends Model<Feedback, IFeedback> {
  @ApiProperty({
    example: 1,
    description: 'Feedback id',
  })
  @Column({
    type: DataType.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  })
  id: number;

  @ApiProperty({
    example: 1,
    description: 'Trainer id',
  })
  @ForeignKey(() => Trainer)
  @Column({
    type: DataType.INTEGER,
  })
  trainerId: number;

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
    example: 5,
    description: 'Stars from 1 to 5',
  })
  @Column({
    type: DataType.INTEGER,
  })
  stars: number;

  @ApiProperty({
    example: 'Good trainer',
    description: 'Feedback comment',
  })
  @Column({
    type: DataType.STRING,
  })
  comment: string;

  @BelongsTo(() => Trainer)
  trainer: Trainer;

  @BelongsTo(() => Client)
  client: Client;
}

export default Feedback;
