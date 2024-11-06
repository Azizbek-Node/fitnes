import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { CreateSportHallReviewDto } from './dto/create-sport-hall_review.dto';
import { UpdateSportHallReviewDto } from './dto/update-sport-hall_review.dto';
import { SportHallReview } from './models/sport-hall_review.model';
import { SportHallService } from '../sport-hall/sport-hall.service';
import { ClientService } from '../client/client.service';
import Client from '../client/models/client.model';
import SportHall from '../sport-hall/models/sport-hall.model';
import { InjectModel } from '@nestjs/sequelize';

@Injectable()
export class SportHallReviewService {
  constructor(
    @InjectModel(SportHallReview)
    private sportHallReviewModel: typeof SportHallReview,
    private clientService: ClientService,
    private sportHallService: SportHallService,
    @InjectModel(SportHall) private sportHallModel: typeof SportHall,
  ) {}

  async create(createSportHallReviewDto: CreateSportHallReviewDto) {
    const client = await this.clientService.findOne(
      createSportHallReviewDto.clientId,
    );
    const sportHall = await this.sportHallService.findOne(
      createSportHallReviewDto.sportHallId,
    );
    if (!client || !sportHall) {
      throw new NotFoundException('Client or Sport Hall not found');
    }
    const sportHallReview = await this.sportHallReviewModel.create(
      createSportHallReviewDto,
    );
    return sportHallReview;
  }

  async likeSportHall(clientId: number, sportHallId: number) {
    const existingLike = await this.sportHallReviewModel.findOne({
      where: { clientId: clientId, sportHallId: sportHallId, likes: 1 },
    });

    if (existingLike) {
      throw new BadRequestException('You have already liked this sport hall.');
    }

    // Increment like count in the sport hall and add a review entry
    await this.sportHallModel.increment('likes', {
      by: 1,
      where: { id: sportHallId },
    });

    // Create a new like entry in the review table
    await this.sportHallReviewModel.create({
      clientId: clientId,
      sportHallId: sportHallId,
      likes: 1,
    });

    return { message: 'Sport hall liked successfully' };
  }

  findAll() {
    return this.sportHallReviewModel.findAll({
      include: [{ model: Client }, { model: SportHall }],
    });
  }

  async findOne(id: number) {
    const sportHallReview = await this.sportHallReviewModel.findByPk(id, {
      include: [{ model: Client }, { model: SportHall }],
    });
    return sportHallReview;
  }

  async update(id: number, updateSportHallReviewDto: UpdateSportHallReviewDto) {
    const sportHallReview = await this.sportHallReviewModel.findByPk(id);
    if (!sportHallReview) {
      throw new NotFoundException('Sport Hall Review not found');
    }
    return sportHallReview.update(updateSportHallReviewDto);
  }

  async remove(id: number) {
    const sportHallReview = await this.sportHallReviewModel.findByPk(id);
    if (!sportHallReview) {
      throw new NotFoundException('Sport Hall Review not found');
    }
    return sportHallReview.destroy();
  }
}
