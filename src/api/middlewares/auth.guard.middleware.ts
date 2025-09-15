import { Request, Response, NextFunction } from 'express';
import { container } from '../../container';
import { ILogger } from '../../application/interfaces/ILogger';
import { TYPES } from '../../shared/constants/types';
import { AuthenticationError } from '../../domain';
import { IAuthService } from '../../application/interfaces/IAuthService';

export function authGuardMiddleware() {
    const authService = container.resolve<IAuthService>(TYPES.AuthService);
    const logger = container.resolve<ILogger>(TYPES.Logger);

    return async (req: Request, res: Response, next: NextFunction) => {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return next(new AuthenticationError('Authorization header missing or invalid'));
        }

        const token = authHeader.split(' ')[1];
        if (!token || token.trim() === '') {
            return next(new AuthenticationError('Authorization header missing or invalid'));
        }

        try {
            const userInfo = await authService.getUserInfo(token);
            (req as any).user = userInfo; // Attach user info to the request
            next();
        } catch (error) {
            logger.error('Authentication failed in authGuardMiddleware', { error });
            next(new AuthenticationError('Invalid token'));
        }
    };
}
