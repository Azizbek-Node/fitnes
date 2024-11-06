import {
  ExecutionContext,
  ForbiddenException,
  createParamDecorator,
} from "@nestjs/common";
import { JwtPayload } from "../types";

export const GetCurentUserId = createParamDecorator(
  (_: undefined, context: ExecutionContext): number => {
    const request = context.switchToHttp().getRequest();

    const user = request?.user as JwtPayload;
    if (!user) {
      throw new ForbiddenException("Token incorrect");
    }
    return user.id;
  }
);
