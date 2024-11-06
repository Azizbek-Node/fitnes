import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateBookingDto } from './dto/create-booking.dto';
import { UpdateBookingDto } from './dto/update-booking.dto';
import { InjectModel } from '@nestjs/sequelize';
import { Booking } from './models/booking.model';
import { Client } from '../client/models/client.model';
import Sport from '../sport/models/sport.model';

@Injectable()
export class BookingsService {
  constructor(
    @InjectModel(Booking) private bookingModel: typeof Booking,
    @InjectModel(Client) private clientModel: typeof Client,
    @InjectModel(Sport) private sportModel: typeof Sport,
  ) {}

  async create(createBookingDto: CreateBookingDto) {
    const client = await this.clientModel.findByPk(createBookingDto.clientId);
    if (!client) {
      throw new NotFoundException('Client not found');
    }
    const sport = await this.sportModel.findByPk(createBookingDto.sportId);
    if (!sport) {
      throw new NotFoundException('Sport not found');
    }
    const booking = this.bookingModel.create(createBookingDto);
    return booking;
  }

  findAll() {
    const bookings = this.bookingModel.findAll({
      include: [
        { model: Sport, attributes: ['name'] },
        { model: Client, attributes: ['fname', 'lname'] },
      ],
    });
    return bookings;
  }

  findOne(id: number) {
    const booking = this.bookingModel.findByPk(id, {
      include: [
        { model: Sport, attributes: ['name'] },
        { model: Client, attributes: ['fname', 'lname'] },
      ],
    });
    return booking;
  }

  update(id: number, updateBookingDto: UpdateBookingDto) {
    const booking = this.bookingModel.update(updateBookingDto, {
      where: { id },
    });
    return booking;
  }

  remove(id: number) {
    const booking = this.bookingModel.destroy({
      where: { id },
    });
    return booking;
  }
}
