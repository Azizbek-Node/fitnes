import { Injectable } from '@nestjs/common';
import { CreateProgressDto } from './dto/create-progress.dto';
import { UpdateProgressDto } from './dto/update-progress.dto';
import Progress from './models/progress.model';
import { InjectModel } from '@nestjs/sequelize';
import Client from '../client/models/client.model';

@Injectable()
export class ProgressService {
  constructor(@InjectModel(Progress) private progressModel: typeof Progress) {}

  async create(createProgressDto: CreateProgressDto) {
    const progress = await this.progressModel.create(createProgressDto);
    return progress;
  }

  findAll() {
    const progress = this.progressModel.findAll({
      include: [{ model: Client }],
    });
    return progress;
  }

  findOne(id: number) {
    const progress = this.progressModel.findByPk(id, {
      include: [{ model: Client }],
    });
    return progress;
  }

  update(id: number, updateProgressDto: UpdateProgressDto) {
    const progress = this.progressModel.update(updateProgressDto, {
      where: { id },
    });
    return progress;
  }

  remove(id: number) {
    const progress = this.progressModel.destroy({ where: { id } });
    return progress;
  }
}
