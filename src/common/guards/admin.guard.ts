import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AdminGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(
    context: ExecutionContext
  ): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const authHeaders = req.headers.authorization;

    if (!authHeaders) {
      throw new UnauthorizedException("Authorization header missing");
    }

    const [bearer, token] = authHeaders.split(" ");

    if (bearer !== "Bearer" || !token) {
      throw new UnauthorizedException("Invalid token format");
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: process.env.ACCESS_TOKEN_KEY,
      });

      if (!payload) {
        throw new UnauthorizedException("Unauthorized admin");
      }

      if (!payload.is_active) {
        throw new ForbiddenException("Ruxsat etilmagan admin");
      }

      req.user = payload; 
      return true; 
    } catch (error) {
      throw new BadRequestException(error.message || "Invalid token");
    }
  }
}
