import express, { Router, Request, Response } from 'express';
import { register, login, generateChallenge } from '../controllers/authController';

const router: Router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/getZKPChallenge', generateChallenge)

export default router;