import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateLimitedDto } from './dto/create-limited.dto';
import { UpdateLimitedDto } from './dto/update-limited.dto';
import { InjectModel } from '@nestjs/sequelize';
import Limited from './models/limited.model';
import SportHall from '../sport-hall/models/sport-hall.model';

@Injectable()
export class LimitedService {
  constructor(
    @InjectModel(Limited) private limitedModel: typeof Limited,
    @InjectModel(SportHall) private sportHallModel: typeof SportHall,
  ) {}
  async create(createLimitedDto: CreateLimitedDto) {
    const sportHall = await this.sportHallModel.findByPk(
      createLimitedDto.sportHallId,
    );
    if (!sportHall) {
      throw new NotFoundException('Sport hall not found');
    }
    const newLimited = await this.limitedModel.create({
      ...createLimitedDto,
      startTime: new Date(createLimitedDto.startTime),
      endTime: new Date(createLimitedDto.endTime),
    });
    await sportHall.$add('limiteds', newLimited.id);
    return newLimited;
  }

  findAll() {
    return this.limitedModel.findAll({ include: { all: true } });
  }

  findOne(id: number) {
    return this.limitedModel.findByPk(id, { include: { all: true } });
  }

  update(id: number, updateLimitedDto: UpdateLimitedDto) {
    return this.limitedModel.update(updateLimitedDto, { where: { id } });
  }

  remove(id: number) {
    return this.limitedModel.destroy({ where: { id } });
  }
}
