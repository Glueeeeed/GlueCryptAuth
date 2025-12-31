import { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv'
dotenv.config({ path: './src/configs/secrets.env' })
import jwt from 'jsonwebtoken';

interface JwtPayload {
    user_uuid: string;
    sessionID: string;
    iat: number;
    exp: number;
}


export const secured = (req: Request, res: Response, next: NextFunction): void => {
    const token : string | undefined = req.cookies.access_token;
    if (!token) {
        console.log('Cookie missing, redirecting /login');
        return res.redirect('/login');
    }

    let decoded: JwtPayload;
    try {
        decoded = jwt.verify(token, process.env.SESSION_SECRET_JWT as string) as JwtPayload;
    } catch (error: any) {
        console.error('Failed verify token:', error.message);
        res.clearCookie('access_token');
        return res.redirect('/login');
    }

    next();

}