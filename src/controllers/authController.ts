import * as jwtLib from 'jsonwebtoken';
import crypto from 'crypto';
import {ec as EC} from 'elliptic';
const ec = new EC('p256');
import db from "../config/database";
import {Request, Response} from "express";
import {getSlicedSecret} from "./keyExchangeController";
import {data_decrypt} from "../utils/cryptoService";
import {ValidateZKP} from "../utils/validation";
import {jwtWrapper} from "../utils/jwtWrapper";
import {secret_verify, secretjwt} from "../config/secrets"
import KeyPair = EC.KeyPair;

interface registerRequest {
    publickey: string;
    login: string;
    iv: string;
    sessionID: string;
}

interface registerResponse {
    response: string;
}

interface loginRequest {
    login: string;
    challenge: string;
    deviceID: string;
    sessionID: string;
    jwt: string;
    iv: string;

}

interface loginResponse {
    token: string;
}

interface ChallengeRequest {
    deviceID: string;

}

interface ChallengeResponse {
    challenge: string;
}




export const  register   =  (req: Request<{}, {}, registerRequest>, res: Response<registerResponse | { error: string }>): void => {
    const encrypted_publicKey : string = req.body.publickey;
    const encrypted_login : string = req.body.login;
    const iv : string = req.body.iv;
    const sessionID : string = req.body.sessionID;
    const secretkey : string = getSlicedSecret(sessionID);

    const publickey : string = data_decrypt(encrypted_publicKey, iv, secretkey);
    const login = data_decrypt(encrypted_login,iv,secretkey);

    registerUSER()

    async function  registerUSER() : Promise<any> {
        const uuid: string = crypto.randomUUID();
        let isValid : string = ValidateZKP(login);
        switch (isValid) {
            case "LoginEmpty":
                return res.status(400).json({error: "User ID cannot be empty."});
            case "InvalidLogin":
                return res.status(400).json({error: "Invalid User ID. User ID cannot be an email address."});
            case "ok":
                break;
            case "LoginNotAllowed":
                return res.status(400).json({error: "User ID contains forbidden words/characters (!@#$%^&*(),.?\":{}|<>) or has less than 3 characters (Max 20) "});
            default:
                return res.status(400).json({error: "Unknown error."});
        }

        try {
            const [users] = await db.execute('SELECT * FROM usersZKP WHERE login = ?', [login]);
            if ((users as any[]).length > 0) {
                return res.status(400).json({ error: 'User ID not available.' });
            }

            await db.execute('INSERT INTO usersZKP (login, publickey, admin, uuid) VALUES (?, ?, False, ?)', [login, publickey, uuid]);
            res.json({response: "Successfully registered! Save your secret key, it will not be shown again!"});
            console.log(`Successfully registered. User: ${uuid}`)
            return;
        } catch (err) {
            console.error(err);
            return res.status(500).json({ error: 'Server Internal Error' });

        }


    }


}

export const  login   = (req: Request<{}, {}, loginRequest>, res: Response<loginResponse | { error: string }>): void => {
    const encrypted_login : string = req.body.login;
    const encrypted_deviceID : string = req.body.deviceID;
    const sessionID : string = req.body.sessionID;
    const encrypted_challenge : string  = req.body.challenge;
    const encrypted_jwt : string  = req.body.jwt;
    const iv : string  = req.body.iv;
    const secretkey : string = getSlicedSecret(sessionID);






    const login : string = data_decrypt(encrypted_login,iv,secretkey);
    const deviceID :string = data_decrypt(encrypted_deviceID,iv,secretkey);
    const signature : string = data_decrypt(encrypted_challenge,iv,secretkey);
    const jwt : string  = data_decrypt(encrypted_jwt,iv,secretkey);

    const payload : any = jwtWrapper(jwt);

    function verifyClientSignature(challenge: string, signatureHex: string, clientPublicKeyHex:string) {
        try {
            const key : KeyPair = ec.keyFromPublic(clientPublicKeyHex, 'hex');
            const signature : string = signatureHex;

            return key.verify(challenge, signature);
        } catch (err) {
            console.error('Client signature verification failed', err);
            return false;
        }
    }

    async function auth() : Promise<any> {
        try {

            const [users] = await db.execute('SELECT * FROM usersZKP WHERE login = ?', [login]);
            const data : any = (users as any[])[0];
            if ((users as any[]).length === 0) {
                return res.status(400).json({ error: 'User ID not found.' });
            }
            const publickey : any  = data.publickey;
            const uuid : any  = data.uuid;

            const challenge : any = payload.challenge;

            const isValid : boolean = verifyClientSignature(challenge,signature, publickey);


            if (isValid === true) {

                const token= jwtLib.sign(
                    {uuid},
                    secretjwt,
                    {expiresIn: '1h'}
                );

                return res.json({token: token})
            } else {
                return res.status(401).json({error: "Invalid Credentials"});
            }




        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Server Internal Error' });
        }
    }

    auth();



}

export const generateChallenge = (req: Request<{}, {}, ChallengeRequest>, res: Response<ChallengeResponse>): any => {
    const deviceID : string = req.body.deviceID;
    const challenge : string = crypto.randomBytes(16).toString('hex');
    const challengeJWT : string = jwtLib.sign(
        {challenge,deviceID},
        secret_verify,
        {expiresIn: '1m'}
    );
    return res.json({challenge: challengeJWT})
}
