/**
 * Key Exchange Controller Module
 * 
 * This module implements the Diffie-Hellman key exchange protocol using elliptic curve
 * cryptography (P-256) to establish secure communication channels between clients and server.
 * It manages session secrets and provides encryption of the application base key.
 * 
 * @module keyExchangeController
 */
import e, { Request, Response } from 'express';
import { ec as EC} from 'elliptic';
import KeyPair = EC.KeyPair;
import {colors} from "../utils/chalk";
import crypto from "crypto";
import {appBaseKeySecret} from '../config/secrets'
import {data_encrypt} from "../utils/cryptoService";

// Initialize elliptic curve with P-256 standard
const ec = new EC('p256');

// In-memory storage for session secrets
const Secrets = new Map<string, string>();


interface KeyExchangeRequest {
    /** The client's public key in hexadecimal format */
    clientPublicKey: string;
}


interface KeyExchangeResponse {
    /** The server's public key in hexadecimal format */
    serverPublicKey: string;
    /** Unique session identifier */
    sessionID: string;
    /** Encrypted application base key */
    baseKey: string;
    /** Initialization vector for base key encryption */
    appBaseIV: string;
}


/**
 * Handles the key exchange process between client and server
 * 
 * This controller function implements the server-side of the Diffie-Hellman key exchange
 * protocol using elliptic curve cryptography. It:
 * 1. Generates a server key pair
 * 2. Derives a shared secret using the client's public key
 * 3. Creates a session ID and stores the secret
 * 4. Encrypts the application base key with the shared secret
 * 5. Returns the necessary data for secure communication
 *
 * @param {Request} req - Express request object containing the client's public key
 * @param {Response} res - Express response object
 * @returns {void}
 */



export const keyExchangeController = (req: Request<{}, {}, KeyExchangeRequest>, res: Response<KeyExchangeResponse | { error: string }>): void => {
    console.group(colors.category('KeyExchangeController'));
    const { clientPublicKey } = req.body;

    try {
        // Generate server key pair for this exchange
        const serverPairKeys : KeyPair = ec.genKeyPair();
        const serverPublicKey : string = serverPairKeys.getPublic('hex');

        // Create key object from client's public key and derive shared secret
        const clientPublicKeyObj : KeyPair = ec.keyFromPublic(clientPublicKey, 'hex');
        const secret : string = serverPairKeys.derive(clientPublicKeyObj.getPublic()).toString('hex');
        const slicedSecret : string = secret.slice(0, 32); // Use first 32 bytes (256 bits) as AES key

        // Generate a unique session ID and store the secret
        const sessionID : string = crypto.randomBytes(10).toString('base64');
        Secrets.set(sessionID, slicedSecret);

        // Generate IV and encrypt the application base key
        const appBaseIV = crypto.randomBytes(16).toString('base64');
        const encrypted_appBaseKey = data_encrypt(appBaseKeySecret, appBaseIV, slicedSecret);

        // Return the key exchange data to the client
        res.json({ 
            serverPublicKey: serverPublicKey, 
            sessionID: sessionID, 
            baseKey: encrypted_appBaseKey, 
            appBaseIV: appBaseIV
        } as KeyExchangeResponse);
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: 'Server Internal Error' });
    }
    console.log(colors.success('Generated session key!'));
    console.groupEnd();
};

/**
 * Retrieves the shared secret for a given session
 * 
 * This function looks up the stored secret associated with a session ID.
 * It's used during the authentication process to access the previously
 * established shared secret for encryption/decryption operations.
 *
 * @param {string} sessionID - The session identifier
 * @returns {string} The shared secret key
 * @throws {Error} If the session ID is invalid or not found
 */



export const getSlicedSecret = (sessionID: string): string => {
    const secret : string | undefined = Secrets.get(sessionID);
    if (!secret) {
        throw new Error('Invalid session ID');
    }
    return secret;
};

/**
 * Removes a session and its associated secret
 * 
 * This function deletes a session from the in-memory storage after
 * authentication is complete or when a session expires. It's an important
 * security measure to ensure that session secrets don't remain in memory
 * indefinitely.
 *
 * @param {string} sessionID - The session identifier to delete
 * @returns {void}
 * @throws {Error} If the session ID is invalid or not found
 */



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

