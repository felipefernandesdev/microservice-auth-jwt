import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { UnouthorizedError } from '../helpers/api-error';
import { userRepository } from '../repositories/userRepository';

type JwtPayload = {
  id: string;
};

export const authMiddleware = async (
  request: Request,
  response: Response,
  next: NextFunction,
) => {
  const { authorization } = request.headers;
  if (!authorization) throw new UnouthorizedError('Not autorized!');

  const token = authorization.split(' ')[1];
  const { id } = jwt.verify(token, process.env.JWT_PASS ?? '') as JwtPayload;

  const user = await userRepository.findOneBy({ id });

  if (!user) throw new UnouthorizedError('Not authorization access');
  const { password: _, ...loggedUser } = user;

  request.user = loggedUser;
  next();
};
