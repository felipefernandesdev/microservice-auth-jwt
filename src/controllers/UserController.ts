import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import { BadRequestError } from '../helpers/api-error';
import { userRepository } from '../repositories/userRepository';

export class UserController {
  async create(request: Request, response: Response) {
    const { name, email, password } = request.body;

    if (!name) throw new BadRequestError('Name is required');

    const userExists = await userRepository.findOneBy({ email });

    if (userExists) throw new BadRequestError('User already exists');

    const hashPassword = await bcrypt.hash(password, 10);

    const newUser = userRepository.create({
      name,
      email,
      password: hashPassword,
    });

    await userRepository.save(newUser);

    const { password: _, ...user } = newUser;

    return response.status(201).json(user);
  }

  async login(request: Request, response: Response) {
    const { email, password } = request.body;

    const user = await userRepository.findOneBy({ email });

    if (!user) throw new BadRequestError('E-mail or Password invalid');

    const verifyPass = await bcrypt.compare(password, user.password);

    if (!verifyPass) throw new BadRequestError('E-mail or Password invalid');

    const token = jwt.sign({ id: user.id }, process.env.JWT_PASS ?? '', {
      expiresIn: '8h',
    });

    const { password: _, ...userLogin } = user;

    return response.status(200).json({
      user: userLogin,
      token: token,
    });
  }

  async getProfile(request: Request, response: Response) {
    return response.status(200).json(request.user)
  }
}
