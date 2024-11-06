import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateTrainerDto } from './dto/create-trainer.dto';
import { UpdateTrainerDto } from './dto/update-trainer.dto';
import { InjectModel } from '@nestjs/sequelize';
import Trainer from './models/trainer.model';
import SportHall from '../sport-hall/models/sport-hall.model';

@Injectable()
export class TrainersService {
  constructor(
    @InjectModel(Trainer) private trainerModel: typeof Trainer,
    @InjectModel(SportHall) private sportHallModel: typeof SportHall,
  ) {}

  async create(createTrainerDto: CreateTrainerDto) {
    const sportHall = await this.sportHallModel.findByPk(
      createTrainerDto.sportHallId,
    );
    if (!sportHall) {
      throw new NotFoundException('Sport hall not found');
    }
    const trainer = await this.trainerModel.create(createTrainerDto);
    return trainer;
  }

  async findAll() {
    const trainers = await this.trainerModel.findAll({
      include: [{ model: SportHall, attributes: ['name'] }],
    });
    return trainers;
  }

  async findOne(id: number) {
    const trainer = await this.trainerModel.findByPk(id, {
      include: [{ model: SportHall, attributes: ['name'] }],
    });
    return trainer;
  }

  async update(id: number, updateTrainerDto: UpdateTrainerDto) {
    const trainer = await this.trainerModel.findByPk(id);
    if (!trainer) {
      throw new NotFoundException('Trainer not found');
    }
    await trainer.update(updateTrainerDto);
    return trainer;
  }

  async remove(id: number) {
    const trainer = await this.trainerModel.findByPk(id);
    if (!trainer) {
      throw new NotFoundException('Trainer not found');
    }
    await trainer.destroy();
    return trainer;
  }
}
