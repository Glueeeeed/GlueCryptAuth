/**
 * Cryptographic Service Module
 * 
 * This module provides encryption and decryption utilities for the GlueCryptAuth system.
 * It implements AES-CBC encryption with base64 encoding for secure data transmission
 * between client and server components.
 * 
 * @module cryptoService
 */
import * as forge from 'node-forge';

/**
 * Decrypts data using AES-CBC algorithm
 * 
 * This function decrypts base64-encoded data using the AES-CBC algorithm
 * with the provided initialization vector and secret key.
 * 
 * @param {string} data - Base64-encoded encrypted data
 * @param {string} iv - The initialization vector in base64 format
 * @param {string} secretkey - The secret key used for decryption
 * @returns {string} The decrypted data as a string
 * @throws {Error} If decryption fails
 */
export function data_decrypt(data: string, iv: string, secretkey: string): string {
    // Decode the base64-encoded encrypted data
    const encryptedBytes = forge.util.decode64(data);

    // Create a decipher object with AES-CBC algorithm
    const decrypt = forge.cipher.createDecipher('AES-CBC', secretkey);

    // Initialize the decipher with the provided IV
    decrypt.start({ iv: forge.util.createBuffer(iv) });

    // Update the decipher with the encrypted data
    decrypt.update(forge.util.createBuffer(encryptedBytes));

    // Finalize the decryption process
    const success = decrypt.finish();

    if (success) {
        return decrypt.output.toString();
    } else {
        throw new Error('Decryption Failed');
    }
}

/**
 * Encrypts data using AES-CBC algorithm
 * 
 * This function encrypts data using the AES-CBC algorithm with the provided
 * initialization vector and secret key, then encodes the result as base64.
 * 
 * @param {string} data - The data to encrypt
 * @param {string} iv - The initialization vector in base64 format
 * @param {string} secretkey - The secret key used for encryption
 * @returns {string} Base64-encoded encrypted data
 * @throws {Error} If encryption fails
 */
export function data_encrypt(data: string, iv: string, secretkey: string): string {
    // Create a cipher object with AES-CBC algorithm
    const encrypt = forge.cipher.createCipher('AES-CBC', secretkey);
    
    // Initialize the cipher with the provided IV
    encrypt.start({ iv: forge.util.createBuffer(iv) });
    
    // Update the cipher with the data to encrypt
    encrypt.update(forge.util.createBuffer(data));
    
    // Finalize the encryption process
    const success = encrypt.finish();
    
    if (success) {
        // Encode the encrypted data as base64
        return forge.util.encode64(encrypt.output.data);
    } else {
        throw new Error('Encryption Failed');
    }
}

