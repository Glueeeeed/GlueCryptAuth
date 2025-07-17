import express, { Router, Request, Response } from 'express';
import { keyExchangeController } from '../controllers/keyExchangeController';

const router: Router = express.Router();

router.post('/keyexchange', keyExchangeController);

export default router;