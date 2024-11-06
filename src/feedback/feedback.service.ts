import { Injectable } from '@nestjs/common';
import { CreateFeedbackDto } from './dto/create-feedback.dto';
import { UpdateFeedbackDto } from './dto/update-feedback.dto';
import { InjectModel } from '@nestjs/sequelize';
import Feedback from './models/feedback.model';
import Trainer from '../trainers/models/trainer.model';
import Client from '../client/models/client.model';

@Injectable()
export class FeedbackService {
  constructor(
    @InjectModel(Feedback) private feedbackRepository: typeof Feedback,
  ) {}

  create(createFeedbackDto: CreateFeedbackDto) {
    const feedback = this.feedbackRepository.create(createFeedbackDto);
    return feedback;
  }

  findAll() {
    const feedbacks = this.feedbackRepository.findAll({
      include: [Trainer, Client],
    });
    return feedbacks;
  }

  findOne(id: number) {
    const feedback = this.feedbackRepository.findByPk(id, {
      include: [Trainer, Client],
    });
    return feedback;
  }

  update(id: number, updateFeedbackDto: UpdateFeedbackDto) {
    const feedback = this.feedbackRepository.update(updateFeedbackDto, {
      where: { id },
    });
    return feedback;
  }

  remove(id: number) {
    const feedback = this.feedbackRepository.destroy({
      where: { id },
    });
    return feedback;
  }
}
