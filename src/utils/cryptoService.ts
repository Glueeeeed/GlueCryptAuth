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

export function data_decrypt(data: string, iv: string, secretkey: string): string {
    try {
        let gcmIv = iv;
        if (iv.length > 12) {
            gcmIv = iv.substring(0, 12);
        }

        const encryptedBytes = forge.util.decode64(data);
        

        const tag = encryptedBytes.slice(0,16);
        const bytes = encryptedBytes.slice(16, encryptedBytes.length);
        

        const decrypt = forge.cipher.createDecipher('AES-GCM', secretkey);
        

        decrypt.start({
            iv: forge.util.createBuffer(gcmIv),
            tag: forge.util.createBuffer(tag),
            tagLength: 128 // 128 bits (16 bytes)
        });


        decrypt.update(forge.util.createBuffer(bytes));
        

        const success = decrypt.finish();
        

        if (!success) {
            throw new Error('Authentication failed - data may have been tampered with');
        }
        
        return decrypt.output.toString();
    } catch (error) {
        console.error("Decryption error:", error);
        throw error;
    }
}


export function data_encrypt(data: string, iv: string, secretkey: string): string {
    try {
        // For GCM, IV should be 12 bytes
        let gcmIv = iv;
        if (iv.length > 12) {
            gcmIv = iv.substring(0, 12);
        }


        const encrypt = forge.cipher.createCipher('AES-GCM', secretkey);
        

        encrypt.start({
            iv: forge.util.createBuffer(gcmIv),
            tagLength: 128
        });
        

        encrypt.update(forge.util.createBuffer(data));
        

        const success = encrypt.finish();
        
        if (!success) {
            throw new Error('Encryption Failed');
        }
        

        const tag = encrypt.mode.tag.getBytes();

        const encryptedData = tag + encrypt.output.getBytes();
        return forge.util.encode64(encryptedData);
    } catch (error) {
        console.error("Encryption error:", error);
        throw error;
    }
}

