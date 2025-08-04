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

/**
 * Interface defining the expected request body for user registration
 * 
 * @interface registerRequest
 */
interface registerRequest {
    /** The user's encrypted public key */
    publickey: string;
    /** The encrypted user login/username */
    login: string;
    /** Initialization vector used for encryption */
    iv: string;
    /** Session identifier from key exchange */
    sessionID: string;
}

/**
 * Interface defining the response structure for successful registration
 * 
 * @interface registerResponse
 */
interface registerResponse {
    /** Response message indicating registration status */
    response: string;
    /** Base key for client-side key derivation */
    basekey: string;
}

/**
 * Interface defining the expected request body for user login
 * 
 * @interface loginRequest
 */
interface loginRequest {
    /** The encrypted user login/username */
    login: string;
    /** The encrypted signed challenge */
    challenge: string;
    /** The encrypted device identifier */
    deviceID: string;
    /** Session identifier from key exchange */
    sessionID: string;
    /** The encrypted JWT challenge token */
    jwt: string;
    /** Initialization vector used for encryption */
    iv: string;
}

/**
 * Interface defining the response structure for successful login
 * 
 * @interface loginResponse
 */
interface loginResponse {
    /** Authentication token for subsequent API requests */
    token: string;
    /** Base key for client-side key derivation */
    basekey: string;
}

/**
 * Interface defining the expected request body for challenge generation
 * 
 * @interface ChallengeRequest
 */
interface ChallengeRequest {
    /** The device identifier */
    deviceID: string;
}

/**
 * Interface defining the response structure for challenge generation
 * 
 * @interface ChallengeResponse
 */
interface ChallengeResponse {
    /** The challenge token to be signed by the client */
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
    // Extract encrypted data from request
    const encrypted_publicKey : string = req.body.publickey;
    const encrypted_login : string = req.body.login;
    const iv : string = req.body.iv;
    const sessionID : string = req.body.sessionID;
    
    // Get the session key for decryption
    const secretkey : string = getSlicedSecret(sessionID);

    console.group(colors.category('AuthController'));
    console.log(colors.warning(encrypted_publicKey));
    console.groupEnd()

    // Decrypt the public key and login
    const publickey : string = data_decrypt(encrypted_publicKey, iv, secretkey);
    const login = data_decrypt(encrypted_login, iv, secretkey);

    // Process the registration
    registerUSER()

    /**
     * Inner function that handles the actual registration process
     * 
     * @returns {Promise<any>} Promise that resolves when registration is complete
     */
    async function registerUSER() : Promise<any> {
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
    // Extract encrypted data from request
    const encrypted_login : string = req.body.login;
    const encrypted_deviceID : string = req.body.deviceID;
    const sessionID : string = req.body.sessionID;
    const encrypted_challenge : string  = req.body.challenge;
    const encrypted_jwt : string  = req.body.jwt;
    const iv : string  = req.body.iv;
    
    // Get the session key for decryption
    const secretkey : string = getSlicedSecret(sessionID);

    // Decrypt all the encrypted fields
    const login : string = data_decrypt(encrypted_login, iv, secretkey);
    const deviceID :string = data_decrypt(encrypted_deviceID, iv, secretkey);
    const signature : string = data_decrypt(encrypted_challenge, iv, secretkey);
    const jwt : string  = data_decrypt(encrypted_jwt, iv, secretkey);

    // Extract the challenge from the JWT
    const payload : any = jwtWrapper(jwt);

    /**
     * Verifies the client's signature of the challenge using their public key
     * 
     * This is the core of the Zero-Knowledge Proof verification, where we confirm
     * that the client possesses the private key corresponding to their public key
     * without the private key ever being transmitted.
     * 
     * @param {string} challenge - The challenge string that was signed
     * @param {string} signatureHex - The signature in hexadecimal format
     * @param {string} clientPublicKeyHex - The client's public key in hexadecimal format
     * @returns {boolean} True if the signature is valid, false otherwise
     */
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

    /**
     * Performs the authentication process
     * 
     * This inner function handles the database lookup, signature verification,
     * and token generation for successful authentication.
     * 
     * @returns {Promise<any>} Promise that resolves when authentication is complete
     */
    async function auth() : Promise<any> {
        try {

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
 * Generates a cryptographic challenge for Zero-Knowledge Proof authentication
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
    // Extract the device ID from the request
    const deviceID : string = req.body.deviceID;
    
    // Generate a random challenge string
    const challenge : string = crypto.randomBytes(16).toString('hex');
    
    // Create a JWT containing the challenge and device ID
    // The JWT expires in 30 seconds to prevent replay attacks
    const challengeJWT : string = jwtLib.sign(
        {challenge, deviceID},
        challengeSecretJwt,
        {expiresIn: '30s'}
    );
    
    // Return the challenge JWT to the client
    return res.json({challenge: challengeJWT})
}


