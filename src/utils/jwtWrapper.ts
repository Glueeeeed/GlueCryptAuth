/**
 * JWT Token Decoder Module
 * 
 * This module provides functionality to decode and extract payload data from JWT tokens
 * used in the GlueCryptAuth system.
 * 
 * @module jwtWrapper
 */

/**
 * Decodes and extracts the payload from a JWT token
 * 
 * This function parses a JWT token, extracts the payload portion,
 * decodes it from base64url format, and returns the parsed JSON object.
 * 
 * @param {string} token - The JWT token to decode
 * @returns {object} The decoded payload as a JavaScript object
 * @throws {Error} If the token is malformed or cannot be parsed
 */
export function jwtWrapper(token: string) {
    // Extract the payload part (second segment) of the JWT
    const base64Url = token.split('.')[1];
    
    // Convert from base64url to base64
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    
    // Decode the base64 string to a UTF-8 string
    const jsonPayload = Buffer.from(base64, 'base64').toString('utf-8');
    
    // Parse the JSON string into an object
    const payload = JSON.parse(jsonPayload);

    return payload;
}