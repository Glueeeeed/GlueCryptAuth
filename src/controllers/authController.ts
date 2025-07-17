import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import db from "../config/database";
import {Request, Response} from "express";
import {getSlicedSecret} from "./keyExchangeController";
import {data_decrypt} from "../utils/cryptoService";
import {ValidateZKP} from "../utils/validation";

interface registerRequest {
    publickey: string;
    login: string;
    iv: string;
    sessionID: string;
}

interface registerResponse {
    response: string;
}



export const  register   =  (req: Request<{}, {}, registerRequest>, res: Response<registerResponse | { error: string }>): void => {
    const encrypted_publicKey = req.body.publickey;
    const encrypted_login = req.body.login;
    const iv = req.body.iv;
    const sessionID = req.body.sessionID;
    const secretkey = getSlicedSecret(sessionID);

    const publickey = data_decrypt(encrypted_publicKey, iv, secretkey);
    const login = data_decrypt(encrypted_login,iv,secretkey);
    console.log(publickey);

     async function  registerUSER() : Promise<void> {
        const uuid: string = crypto.randomUUID();
        let isValid : string = ValidateZKP(login);
         switch (isValid) {
             case "LoginEmpty":
                  res.status(400).json({error: "User ID cannot be empty."});
                  break;
             case "InvalidLogin":
                  res.status(400).json({error: "Invalid User ID. User ID cannot be an email address."});
                  break;
             case "ok":
                 break;
             case "LoginNotAllowed":
                  res.status(400).json({error: "User ID contains forbidden words/characters (!@#$%^&*(),.?\":{}|<>) or has less than 3 characters "});
                  break;
             default:
                  res.status(400).json({error: "Unknown error."});
         }

         try {
             const [users] = await db.execute('SELECT * FROM usersZKP WHERE login = ?', [login]);
             if ((users as any[]).length > 0) {
                  res.status(400).json({ error: 'User ID not available.' });
             }

             await db.execute('INSERT INTO usersZKP (login, publickey, admin, uuid) VALUES (?, ?, False, ?)', [login, publickey, uuid]);
             res.json({response: "Successfully registered! Save your secret key, it will not be shown again!"});
             console.log(`Successfully registered. User: ${uuid}`)
         } catch (err) {
             console.error(err);
             res.status(500).json({ error: (err as Error).message });
         }


     }
      registerUSER()






}
