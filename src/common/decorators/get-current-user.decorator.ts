import {
  ExecutionContext,
  ForbiddenException,
  createParamDecorator,
} from "@nestjs/common";
import { JwtPayload, JwtPayloadWithRefreshToken } from "../types";

export const GetCurentUser = createParamDecorator(
  (data: keyof JwtPayloadWithRefreshToken, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();

    const user = request?.user as JwtPayload;
    // console.log(data);
    
    if (!user) {
      throw new ForbiddenException("Token incorrect");
    }
    if (!data) {
      return user;
    }
    return user[data];
  }
);
