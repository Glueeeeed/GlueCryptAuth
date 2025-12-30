/**
 * JWT Token Decoder Module
 * 
 * This module provides functionality to decode and extract payload data from JWT tokens
 * used in the GlueCryptAuth system.
 * 
 * @module jwtWrapper
 */


export function jwtWrapper(token: string) {
    const base64Url = token.split('.')[1];
    
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    
    const jsonPayload = Buffer.from(base64, 'base64').toString('utf-8');
    
    const payload = JSON.parse(jsonPayload);

    return payload;
}