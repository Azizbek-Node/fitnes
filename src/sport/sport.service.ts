import { Injectable } from '@nestjs/common';
import { CreateSportDto } from './dto/create-sport.dto';
import { UpdateSportDto } from './dto/update-sport.dto';
import { Sport } from './models/sport.model';
import { InjectModel } from '@nestjs/sequelize';

@Injectable()
export class SportService {
  constructor(@InjectModel(Sport) private sportModel: typeof Sport) {}

  create(createSportDto: CreateSportDto) {
    return this.sportModel.create(createSportDto);
  }

  findAll() {
    return this.sportModel.findAll({ include: { all: true } });
  }

  findOne(id: number) {
    return this.sportModel.findByPk(id, { include: { all: true } });
  }

  update(id: number, updateSportDto: UpdateSportDto) {
    return this.sportModel.update(updateSportDto, { where: { id } });
  }

  remove(id: number) {
    return this.sportModel.destroy({ where: { id } });
  }
}
