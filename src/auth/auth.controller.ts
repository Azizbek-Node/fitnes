import { Controller, Post, Body, Res, BadRequestException, Param, Get } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiOperation } from '@nestjs/swagger';
import { AdminSigninDto } from './dto/admin-signin.dto';
import { Response } from 'express';
import { CreateAdminDto } from '../admin/dto/create-admin.dto';
import { Admin } from '../admin/models/admin.model';
import { CreateClientDto } from '../client/dto/create-client.dto';
import { ClientSigninDto } from './dto/client-signin.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  //-------------------------Admin----------------------------
  @ApiOperation({
    summary: 'Generate token',
    description: 'Generate token',
  })
  @Post('generate-token')
  async generateToken(@Body() admin: Admin) {
    return this.authService.generateToken(admin);
  }

  @Post('admin-signin')
  @ApiOperation({
    summary: 'Admin signin',
    description: 'Admin signin',
  })
  async adminSignin(
    @Body() signInAdminDto: AdminSigninDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.signIn(signInAdminDto, res);
  }

  @Post('admin-signup')
  @ApiOperation({
    summary: 'Admin signup',
    description: 'Admin signup',
  })
  async adminSignup(
    @Body() createAdminDto: CreateAdminDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.signUp(createAdminDto, res);
  }
  //-------------------------Client----------------------------
  @ApiOperation({
    summary: 'Client signup',
    description: 'Client signup',
  })
  @Post('client-signup')
  async clientSignup(
    @Body() createClientDto: CreateClientDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.clientSignUp(createClientDto, res);
  }

  @ApiOperation({
    summary: 'Client signin',
    description: 'Client signin',
  })
  @Post('client-signin')
  async clientSignin(
    @Body() signInClientDto: ClientSigninDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.clientSignIn(signInClientDto, res);
  }

  @ApiOperation({
    summary: 'Client signout',
    description: 'Client signout',
  })
  @Post('client-signout')
  async clientSignout(
    @Body() refresh_token: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.clientSignOut(refresh_token, res);
  }

  @ApiOperation({
    summary: 'Activate client',
    description: 'Activate client',
  })
  @Get('activate/:link')
  activateClient(@Param('link') link: string) {
    return this.authService.activateClient(link);
  }

  @ApiOperation({
    summary: 'Refresh token',
    description: 'Refresh token',
  })
  @Post('refresh-token')
  refreshTokenClient(
    @Body() refresh_token: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.refreshToken(refresh_token, res);
  }
}
