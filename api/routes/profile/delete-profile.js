import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { UserModel } from '../../models/User.js';

const JWT_SECRET = process.env.JWT_SECRET;

export const deleteUser = Router();

deleteUser.delete(
  '/',
  async (request, response) => {
    try {
      // Recibir el token JWT 
      const token = request.headers.authorization.split(' ')[1];

      // Verificar y decodificar el JWT
      const decodedToken = jwt.verify(token, JWT_SECRET);

      //Recibir  el ID del usuario del JWT decodificado
      const userId = decodedToken.userId;

      // Eliminar al usuario de la base de datos utilizando el ID de usuario
      await UserModel.findByIdAndDelete(userId);

      return response.status(200).json({
        message: 'El usuario fue eliminado',
      });
    } catch (error) {
      console.error(`[deleteUser]: ${error}`);

      if (error instanceof jwt.JsonWebTokenError) {
        return response.status(401).json({
          error: 'Token inválido',
        });
      }

      return response.status(500).json({
        error: 'Ocurrió un error',
      });
    }
  }
);
