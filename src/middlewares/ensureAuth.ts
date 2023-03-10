import { NextFunction, Request, Response } from "express";
import { GetPublicKeyOrSecret, Secret, verify } from "jsonwebtoken";
import { authConfig } from "../configs/authConfig";
import AppError from "../errors/appError";
import { TokenPayloadDTO } from "../interfaces";

export class Authentication {
  constructor() {}

  static ensureAuth(req: Request, res: Response, next: NextFunction): void {
    const authHeader: string | undefined = req.headers.authorization

    if(!authHeader) {
      throw new AppError('Authorization token not informed', 401)
    }

    try {
      const [, token] = authHeader.split(' ')
      const {secret} = authConfig

      const decoded = verify(token, secret)
      const {sub} = decoded as TokenPayloadDTO

      req.user = {
        id: sub
      }
      
    } catch (error) {
      throw new AppError('Invalid authorization token or sent in a wrong way', 401)
    }
  }
}