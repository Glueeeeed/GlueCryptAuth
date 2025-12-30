/**
 * Authentication Controller Module
 * 
 * This module implements Zero-Knowledge Proof (ZKP) authentication using elliptic curve
 * cryptography. It handles user registration, login, and challenge generation for the
 * GlueCryptAuth system. The authentication flow is designed to ensure that private keys
 * are never directly transmitted over the network.
 * 
 * @module authController
 */

import * as jwtLib from 'jsonwebtoken';
import crypto from 'crypto';
import {ec as EC} from 'elliptic';
const ec = new EC('p256');
import db from "../config/database";
import {Request, Response} from "express";
import {deleteSecret, getSlicedSecret} from "./keyExchangeController";
import {data_decrypt} from "../utils/cryptoService";
import {ValidateZKP} from "../utils/validation";
import {jwtWrapper} from "../utils/jwtWrapper";
import {challengeSecretJwt, sessionSecretJwt, appBaseKeySecret} from "../config/secrets"
import KeyPair = EC.KeyPair;
import {colors} from "../utils/chalk";
import {disabled, onlyAdmin} from "../config/settings";


interface registerRequest {
    publickey: string;
    login: string;
    iv: string;
    sessionID: string;
}


interface registerResponse {
    response: string;
    basekey: string;
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
    basekey: string;
}

interface ChallengeRequest {
    deviceID: string;
}

interface ChallengeResponse {
    challenge: string;
}




/**
 * Handles user registration with Zero-Knowledge Proof authentication
 * 
 * This controller function processes user registration requests by:
 * 1. Decrypting the encrypted data using the session key
 * 2. Validating the user login information
 * 3. Checking if the user already exists
 * 4. Storing the user's public key and login in the database
 * 5. Returning a success response with the base key
 *
 * @param {Request} req - Express request object containing registration data
 * @param {Response} res - Express response object
 * @returns {void}
 */



export const register = (req: Request<{}, {}, registerRequest>, res: Response<registerResponse | { error: string }>): void => {
    const encrypted_publicKey : string = req.body.publickey;
    const encrypted_login : string = req.body.login;
    const iv : string = req.body.iv;
    const sessionID : string = req.body.sessionID;
    
    const secretkey : string = getSlicedSecret(sessionID);

    console.group(colors.category('AuthController'));
    console.log(colors.warning(encrypted_publicKey));
    console.groupEnd()

    const publickey : string = data_decrypt(encrypted_publicKey, iv, secretkey);
    const login = data_decrypt(encrypted_login, iv, secretkey);

    registerUSER()


    async function registerUSER() : Promise<any> {
        if (disabled) {
            console.group(colors.category('AuthController'));
            console.log(colors.warning('Registration disabled. Refused request'));
            console.groupEnd()
            deleteSecret(sessionID);
            return res.status(400).json({error: 'Registration is currently disabled'});
        }
        const uuid: string = crypto.randomUUID();
        let isValid : string = ValidateZKP(login);
        switch (isValid) {
            case "LoginEmpty":
                console.group(colors.category('AuthController'));
                console.log(colors.warning(`Validation Failed. `))
                console.groupEnd()
                deleteSecret(sessionID);
                return res.status(400).json({error: "User ID cannot be empty."});
            case "InvalidLogin":
                console.group(colors.category('AuthController'));
                console.log(colors.warning(`Validation Failed.`))
                console.groupEnd()
                deleteSecret(sessionID);
                return res.status(400).json({error: "Invalid User ID. User ID cannot be an email address."});
            case "ok":
                break;
            case "LoginNotAllowed":
                console.group(colors.category('AuthController'));
                console.log(colors.warning(`Validation Failed.`))
                console.groupEnd()
                deleteSecret(sessionID);
                return res.status(400).json({error: "User ID contains forbidden words/characters (!@#$%^&*(),.?\":{}|<>) or has less than 3 characters (Max 20) "});
            case "Error":
                console.group(colors.category('AuthController'));
                console.log(colors.warning(`Validation Failed.`))
                console.groupEnd()
                deleteSecret(sessionID);
                return res.status(400).json({error: "Server Error."});
            default:
                console.group(colors.category('AuthController'));
                console.log(colors.warning(`Validation Failed.`))
                console.groupEnd()
                deleteSecret(sessionID);
                return res.status(400).json({error: "Unknown error."});
        }

        try {
            const [users] = await db.execute('SELECT * FROM usersZKP WHERE login = ?', [login]);
            if ((users as any[]).length > 0) {
                deleteSecret(sessionID);
                return res.status(400).json({ error: 'User ID not available.' });
            }

            await db.execute('INSERT INTO usersZKP (login, publickey, admin, uuid) VALUES (?, ?, False, ?)', [login, publickey, uuid]);
            res.json({response: "Successfully registered! Save your secret key, it will not be shown again!", basekey: appBaseKeySecret});
            console.group(colors.category('AuthController'));
            console.log(colors.success(`Successfully registered. User: ${uuid}`))
            deleteSecret(sessionID);
            console.groupEnd()
            return;
        } catch (err) {
            console.group(colors.category('AuthController'));
            console.error(colors.error(err));
            console.groupEnd()
            deleteSecret(sessionID);
            return res.status(500).json({ error: 'Server Internal Error' });

        }


    }


}

/**
 * Handles user login with Zero-Knowledge Proof authentication
 * 
 * This controller function processes login requests by:
 * 1. Decrypting the encrypted data using the session key
 * 2. Extracting the challenge and signature
 * 3. Retrieving the user's public key from the database
 * 4. Verifying the signature against the challenge using the public key
 * 5. Generating and returning a JWT token upon successful authentication
 *
 * @param {Request} req - Express request object containing login data
 * @param {Response} res - Express response object
 * @returns {void}
 */



export const login = (req: Request<{}, {}, loginRequest>, res: Response<loginResponse | { error: string }>): void => {
    const encrypted_login : string = req.body.login;
    const encrypted_deviceID : string = req.body.deviceID;
    const sessionID : string = req.body.sessionID;
    const encrypted_challenge : string  = req.body.challenge;
    const encrypted_jwt : string  = req.body.jwt;
    const iv : string  = req.body.iv;
    
    const secretkey : string = getSlicedSecret(sessionID);

    const login : string = data_decrypt(encrypted_login, iv, secretkey);
    const deviceID :string = data_decrypt(encrypted_deviceID, iv, secretkey);
    const signature : string = data_decrypt(encrypted_challenge, iv, secretkey);
    const jwt : string  = data_decrypt(encrypted_jwt, iv, secretkey);

    const payload : any = jwtWrapper(jwt);





    function verifyClientSignature(challenge: string, signatureHex: string, clientPublicKeyHex:string) {
        try {
            const key : KeyPair = ec.keyFromPublic(clientPublicKeyHex, 'hex');
            const signature : string = signatureHex;

            return key.verify(challenge, signature);
        } catch (err) {
            console.group(colors.category('AuthController'));
            console.error(colors.error('Client signature verification failed', err));
            console.groupEnd()
            return false;
        }
    }


    async function checkOnlyAdmin(login: string) : Promise<any> {
        if (onlyAdmin) {
            const [users] = await db.execute('SELECT admin FROM usersZKP WHERE login = ?', [login]);
            const data : any = (users as any[])[0];
            const isAdmin: any = data.admin;
            if (isAdmin === 0) {
                return "notAdmin";
            } else {
                return "ok";
            }
        } else {
            return "functionDisabled";
        }
    }


    async function auth() : Promise<any> {
        try {

            let status : any = await checkOnlyAdmin(login);
            switch (status) {
                case "notAdmin":
                    deleteSecret(sessionID);
                    return res.status(400).json({error: "Access Denied. Log in is currently disabled."});
                case "ok":
                    console.group(colors.category('AuthController'));
                    console.error(colors.success('Admin validation passed'));
                    console.groupEnd()
                    break;
                case "functionDisabled":
                    console.group(colors.category('AuthController'));
                    console.error(colors.warning('checkAdmin disabled skipping'));
                    console.groupEnd()
                    break;
                default:
                    status = false;
                    break;
            }

            if (status === false) {
                throw new Error('Unauthorized');
            }

            const [users] = await db.execute('SELECT * FROM usersZKP WHERE login = ?', [login]);
            const data : any = (users as any[])[0];
            if ((users as any[]).length === 0) {
                deleteSecret(sessionID);
                return res.status(400).json({ error: 'User ID not found.' });
            }
            const publickey : any  = data.publickey;
            const uuid : any  = data.uuid;

            const challenge : any = payload.challenge;

            const isValid : boolean = verifyClientSignature(challenge,signature, publickey);


            if (isValid === true) {

                const token= jwtLib.sign(
                    {uuid},
                    sessionSecretJwt,
                    {expiresIn: '15m'}
                );
                deleteSecret(sessionID);
                return res.json({token: token, basekey: appBaseKeySecret})
            } else {
                deleteSecret(sessionID);
                return res.status(401).json({error: "Invalid Credentials"});
            }




        } catch (err) {
            console.group(colors.category('AuthController'));
            console.error(colors.error(err));
            console.groupEnd();
            deleteSecret(sessionID);
            res.status(500).json({ error: 'Server Internal Error' });


        }
    }

    auth();



}

/**
 * Generates a cryptographic challenge
 * 
 * This controller function creates a random challenge that the client must sign
 * with their private key to prove their identity. The challenge is:
 * 1. Generated as a random hex string
 * 2. Combined with the device ID for additional security
 * 3. Wrapped in a short-lived JWT for integrity and expiration control
 * 4. Returned to the client for signing
 *
 * @param {Request} req - Express request object containing the device ID
 * @param {Response} res - Express response object
 * @returns {any} Response containing the challenge JWT
 */



export const generateChallenge = (req: Request<{}, {}, ChallengeRequest>, res: Response<ChallengeResponse>): any => {
    const deviceID : string = req.body.deviceID;

    const challenge : string = crypto.randomBytes(16).toString('hex');
    

    const challengeJWT : string = jwtLib.sign(
        {challenge, deviceID},
        challengeSecretJwt,
        {expiresIn: '30s'}
    );

    return res.json({challenge: challengeJWT})

}




