import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateSportHallDto } from './dto/create-sport-hall.dto';
import { UpdateSportHallDto } from './dto/update-sport-hall.dto';
import { InjectModel } from '@nestjs/sequelize';
import { SportHall } from './models/sport-hall.model';
import { AddRemoveSportinhallDto } from './dto/add-remove-sportinhall.dto';
import { Sport } from '../sport/models/sport.model';

@Injectable()
export class SportHallService {
  constructor(
    @InjectModel(SportHall) private sportHallModel: typeof SportHall,
    @InjectModel(Sport) private sportModel: typeof Sport,
  ) {}

  async create(createSportHallDto: CreateSportHallDto) {
    const sportHall = await this.sportHallModel.findOne({
      where: { name: createSportHallDto.name },
    });
    if (sportHall) {
      throw new BadRequestException('Sport hall already exists');
    }
    const newSportHall = await this.sportHallModel.create(createSportHallDto);
    return newSportHall;
  }

  async findAll() {
    const sportHalls = await this.sportHallModel.findAll({
      include: { all: true },
    });
    return { sportHalls };
  }

  async findOne(id: number) {
    const sportHall = await this.sportHallModel.findByPk(id, {
      include: { all: true },
    });
    return { sportHall };
  }

  async update(id: number, updateSportHallDto: UpdateSportHallDto) {
    const sportHall = await this.sportHallModel.findByPk(id);
    if (!sportHall) {
      throw new NotFoundException('Sport hall not found');
    }
    await sportHall.update(updateSportHallDto);
    return sportHall;
  }

  async remove(id: number) {
    const sportHall = await this.sportHallModel.findByPk(id);
    if (!sportHall) {
      throw new NotFoundException('Sport hall not found');
    }
    await sportHall.destroy();
    return sportHall;
  }

  async addSportinhall(addRemoveSportinhallDto: AddRemoveSportinhallDto) {
    const sport = await this.sportModel.findByPk(
      addRemoveSportinhallDto.sportId,
    );
    const sportHall = await this.sportHallModel.findByPk(
      addRemoveSportinhallDto.sportHallId,
    );
    if (sport && sportHall) {
      await sport.$add('sportHall', sportHall.id);
      const updatedSport = await this.sportModel.findByPk(
        addRemoveSportinhallDto.sportId,
        { include: { all: true } },
      );
      return updatedSport;
    }

    throw new NotFoundException('Sport or sport hall not found');
  }

  async removeSportinhall(addRemoveSportinhallDto: AddRemoveSportinhallDto) {
    const sport = await this.sportModel.findByPk(
      addRemoveSportinhallDto.sportId,
    );
    const sportHall = await this.sportHallModel.findByPk(
      addRemoveSportinhallDto.sportHallId,
    );
    if (sport && sportHall) {
      await sport.$remove('sportHall', sportHall.id);
    }
    throw new NotFoundException('Sport or sport hall not found');
  }
}
