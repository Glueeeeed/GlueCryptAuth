/**
 * Cryptographic Service Module
 * 
 * This module provides encryption and decryption utilities for the GlueCryptAuth system.
 * It implements AES-GCM encryption with base64 encoding for secure data transmission
 * between client and server components.
 * 
 * @module cryptoService
 */
import * as forge from 'node-forge';

/**
 * Decrypts data using AES-GCM algorithm
 * 
 * This function decrypts base64-encoded data using the AES-GCM algorithm
 * with the provided initialization vector and secret key.
 * 
 * @param {string} data - Base64-encoded encrypted data with authentication tag
 * @param {string} iv - The initialization vector
 * @param {string} secretkey - The secret key used for decryption
 * @returns {string} The decrypted data as a string
 * @throws {Error} If decryption fails or authentication fails
 */
export function data_decrypt(data: string, iv: string, secretkey: string): string {
    try {
        // For GCM, IV should be 12 bytes
        let gcmIv = iv;
        if (iv.length > 12) {
            gcmIv = iv.substring(0, 12);
        }
        
        // Decode the base64 data
        const encryptedBytes = forge.util.decode64(data);
        

        // Extract ciphertext and tag (first 16 bytes)
        const tag = encryptedBytes.slice(0,16);
        const bytes = encryptedBytes.slice(16, encryptedBytes.length);
        
        // Create decipher
        const decrypt = forge.cipher.createDecipher('AES-GCM', secretkey);
        
        // Initialize decipher with IV and tag
        decrypt.start({
            iv: forge.util.createBuffer(gcmIv),
            tag: forge.util.createBuffer(tag),
            tagLength: 128 // 128 bits (16 bytes)
        });
        
        // Update with ciphertext
        decrypt.update(forge.util.createBuffer(bytes));
        
        // Finish and verify authentication
        const success = decrypt.finish();
        
        // If authentication failed, throw an error
        if (!success) {
            throw new Error('Authentication failed - data may have been tampered with');
        }
        
        return decrypt.output.toString();
    } catch (error) {
        console.error("Decryption error:", error);
        throw error;
    }
}

/**
 * Encrypts data using AES-GCM algorithm
 * 
 * This function encrypts data using the AES-GCM algorithm with the provided
 * initialization vector and secret key, then encodes the result as base64.
 * 
 * @param {string} data - The data to encrypt
 * @param {string} iv - The initialization vector
 * @param {string} secretkey - The secret key used for encryption
 * @returns {string} Base64-encoded encrypted data with authentication tag
 * @throws {Error} If encryption fails
 */
export function data_encrypt(data: string, iv: string, secretkey: string): string {
    try {
        // For GCM, IV should be 12 bytes
        let gcmIv = iv;
        if (iv.length > 12) {
            gcmIv = iv.substring(0, 12);
        }

        // Create cipher
        const encrypt = forge.cipher.createCipher('AES-GCM', secretkey);
        
        // Initialize cipher with IV
        encrypt.start({
            iv: forge.util.createBuffer(gcmIv),
            tagLength: 128 // 128 bits (16 bytes) for the authentication tag
        });
        
        // Update with data
        encrypt.update(forge.util.createBuffer(data));
        
        // Finish encryption
        const success = encrypt.finish();
        
        if (!success) {
            throw new Error('Encryption Failed');
        }
        
        // Get the authentication tag
        const tag = encrypt.mode.tag.getBytes();
        
        // Combine encrypted data and tag, then encode to base64
        const encryptedData = tag + encrypt.output.getBytes();
        return forge.util.encode64(encryptedData);
    } catch (error) {
        console.error("Encryption error:", error);
        throw error;
    }
}

