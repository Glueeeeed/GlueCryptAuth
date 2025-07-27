import e, { Request, Response } from 'express';
import { ec as EC} from 'elliptic';
import KeyPair = EC.KeyPair;
import {colors} from "../utils/chalk";
import crypto from "crypto";
const ec = new EC('p256');


const Secrets = new Map<string, string>();


interface KeyExchangeRequest {
    clientPublicKey: string;
}


interface KeyExchangeResponse {
    serverPublicKey: string;
    sessionID: string;
}


export const keyExchangeController = (req: Request<{}, {}, KeyExchangeRequest>, res: Response<KeyExchangeResponse | { error: string }>): void => {
    console.group(colors.category('KeyExchangeController'));
    const { clientPublicKey } = req.body;


    try {
        const serverPairKeys : KeyPair = ec.genKeyPair();
        const serverPublicKey : string = serverPairKeys.getPublic('hex');

        const clientPublicKeyObj : KeyPair = ec.keyFromPublic(clientPublicKey, 'hex');
        const secret : string = serverPairKeys.derive(clientPublicKeyObj.getPublic()).toString('hex');
        const slicedSecret : string = secret.slice(0, 32);

        const sessionID : string = crypto.randomBytes(10).toString('base64');
        Secrets.set(sessionID, slicedSecret);


        res.json({ serverPublicKey, sessionID } as KeyExchangeResponse);
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: 'Server Internal Error' });
    }
    console.log(colors.success('Generated session key!'));
    console.groupEnd();

};

export const getSlicedSecret = (sessionID: string): string => {
    const secret : string | undefined = Secrets.get(sessionID);
    if (!secret) {
        throw new Error('Invalid session ID');
    }
    return secret;
};

export const deleteSecret = (sessionID: string) : void => {

    try {
        if (Secrets.delete(sessionID)) {
            console.group(colors.category('KeyExchangeController'));
            console.log(colors.warning(`Cleared session:`, sessionID));
            console.groupEnd();
        } else {
            throw new Error('Invalid session ID');
        }
    } catch (e) {
        console.group(colors.category('KeyExchangeController'));
        console.error(colors.error(e));
        console.group(colors.category('KeyExchangeController'));
    }

}

