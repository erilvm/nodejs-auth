import { Router } from 'express';
import { body,validationResult } from 'express-validator';
import jwt from 'jsonwebtoken';
import { UserModel } from '../../models/User.js';
import dotenv from 'dotenv';
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

export const updateUser = Router();

updateUser.put(
  '/',
  // Validación de los datos de entrada
  body('username').optional().notEmpty().trim(),
  body('password').optional().isLength({ min: 6 }),

  // Actualizar información del usuario según la seccion del JWT
  async (request, response) => {
    try {
      const errors = validationResult(request);
      if (!errors.isEmpty()) {
   return response.status(400).json({ errors: errors.array() });
      }

      //Recibir el JWT 
      const token = request.headers.authorization.split(' ')[1];

      // Verificar y decodificar el JWT
      const decodedToken = jwt.verify(token, JWT_SECRET);

      //Recibir el ID del usuario del JWT decodificado
      const userId = decodedToken.userId;

      // Buscar al usuario en la base de datos utilizando el ID de usuario
      const user = await UserModel.findById(userId);

if (!user) {
          return response.status(404).json({
            error: 'Usuario no encontrado',
          });
        }
  
        // Actualizar la información del usuario con los datos de la solicitud
        if (request.body.username) {
          user.username = request.body.username;//usuario
          user.password = request.body.password;//contraseña
        }
  
        // Guardar los cambios en la base de datos
        await user.save();
  
        // Devolver la información actualizada del usuario
        return response.status(200).json({
          username: user.username,
          password: user.password,
          updatedAt: user.updatedAt,
        });
  
      } catch (error) {
        console.error(`[updateUser]: ${error}`);
  
        if (error instanceof jwt.JsonWebTokenError) {
          return response.status(401).json({
            error: 'Token incorrecto',
          });
        }
  
        return response.status(500).json({
          error: 'Error! Por favor, inténtalo  más tarde',
        });
      }
    }
  );