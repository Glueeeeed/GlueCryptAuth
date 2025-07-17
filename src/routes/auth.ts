import express, { Router, Request, Response } from 'express';
import { register } from '../controllers/authController';

const router: Router = express.Router();

router.post('/register', register);

export default router;