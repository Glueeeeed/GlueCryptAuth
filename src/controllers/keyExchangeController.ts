import e, { Request, Response } from 'express';
import { ec as EC} from 'elliptic';
import KeyPair = EC.KeyPair;
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
    const { clientPublicKey } = req.body;


    try {
        const serverPairKeys : KeyPair = ec.genKeyPair();
        const serverPublicKey : string = serverPairKeys.getPublic('hex');

        const clientPublicKeyObj : KeyPair = ec.keyFromPublic(clientPublicKey, 'hex');
        const secret : string = serverPairKeys.derive(clientPublicKeyObj.getPublic()).toString('hex');
        const slicedSecret : string = secret.slice(0, 32);

        const sessionID : string = Math.random().toString(36).substring(2, 15);
        Secrets.set(sessionID, slicedSecret);


         res.json({ serverPublicKey, sessionID } as KeyExchangeResponse);
    } catch (e) {
         res.status(400).json({ error: (e as Error).message });
    }

};

export const getSlicedSecret = (sessionID: string): string => {
    const secret : string | undefined = Secrets.get(sessionID);
    if (!secret) {
        throw new Error('Invalid session ID');
    }
    return secret;
};

