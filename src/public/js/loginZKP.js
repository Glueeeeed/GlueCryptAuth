
/**
 * GlueCryptAuth - Zero Knowledge Proof Authentication System
 * 
 * This module handles the secure login process using elliptic curve cryptography,
 * zero-knowledge proofs, and multi-factor authentication with device fingerprinting.
 */

// Initialize elliptic curve with P-256 standard
let ec = new elliptic.ec('p256');
// Flag to track if a new key is being generated during the session
let isGeneratedKey = false;

// Setup initial state when DOM is fully loaded
document.addEventListener("DOMContentLoaded", (event) => {
    verifyDeviceID()
    const savedDarkMode = localStorage.getItem('theme') === 'dark';


    if (window.matchMedia("(max-width: 768px)").matches === false) {
        if (savedDarkMode) {
            document.body.classList.add('dark');
            document.body.classList.remove('light');
            document.getElementById("darkModeSwitch").checked = true;
        }
    } else if (window.matchMedia("(max-width: 768px)").matches === true) {
        if (savedDarkMode) {
            document.body.classList.add('dark');
            document.body.classList.remove('light');
            document.getElementById("darkModeSwitch").checked = true;
        }
    }
});

/**
 * Resets the user's authentication key from IndexedDB storage
 * 
 * @returns {Promise<null>} Returns null on error
 */
async function resetKey() {
    try {
        const db = await idb.openDB('gluecrypt', 2, {
            upgrade(db, oldVersion, newVersion, transaction) {
                if (!db.objectStoreNames.contains('keys')) {
                    db.createObjectStore('keys');
                }
            }
        });
        await db.delete('keys', 'privateKey');
        alert('Key reset successfully!');
    } catch (error) {
        console.error('Failed to save:', error);
        return null;
    }
}

/**
 * Decodes a base64url encoded string to UTF-8
 * 
 * @param {string} str - The base64url encoded string
 * @returns {string} The decoded string
 */
function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(str);
    try {
        return decodeURIComponent(escape(decoded));
    } catch {
        return decoded;
    }
}

/**
 * Validates the format of a mnemonic phrase
 * 
 * @param {string} mnemonic - The mnemonic phrase to validate
 * @returns {boolean} True if the mnemonic is valid, false otherwise
 */
function validateMnemonic(mnemonic) {
    if (!mnemonic.includes("-")) {
        return false;
    }

    const array = mnemonic.split('-');

    if (array.length !== 18) {
        return false;
    }

    return true;
}

/**
 * Extracts and decodes the payload from a JWT token
 * 
 * @param {string} token - The JWT token
 * @returns {Object} The decoded payload as a JavaScript object
 * @throws {Error} If the token is invalid
 */
function decodeJwtPayload(token) {
    const payloadBase64Url = token.split('.')[1];
    if (!payloadBase64Url) throw new Error('Invalid token');
    return JSON.parse(base64UrlDecode(payloadBase64Url));
}

/**
 * Toggles between light and dark theme based on user preference
 * Saves the preference to localStorage for persistence
 */
function themeChange() {
    const mode = document.getElementById("darkModeSwitch");
    const modeMobile = document.getElementById("darkModeSwitchMobile");
    const hamburger = document.getElementById("hamburgerDropdownNav");

    if (window.matchMedia("(max-width: 768px)").matches === false) {
        if (mode.checked === true) {
            document.body.classList.add("dark");
            document.body.classList.remove("light");
            localStorage.setItem("theme", "dark");
        }
        else {
            document.body.classList.add("light");
            document.body.classList.remove("dark");
            localStorage.setItem("theme", "light");
        }
    }
}

/**
 * Retrieves the browser fingerprint using ThumbmarkJS
 * 
 * @returns {Promise<Object>} The fingerprint object
 */
async function getFingerprint() {
    const tm = new ThumbmarkJS.Thumbmark();
    const fingerprint = await tm.get();
    return fingerprint;
}

/**
 * Secures a private key using a combination of device fingerprint, device ID, and server-provided base key
 * 
 * This function implements a multi-factor encryption approach where the key can only be
 * decrypted when all three components (fingerprint, deviceID, baseKey) are present.
 * 
 * @param {string} fingerprint - The browser fingerprint
 * @param {string} privateKey - The private key to secure
 * @param {string} deviceID - The unique device identifier
 * @param {string} baseKey - The server-provided component of the encryption key
 * @returns {Object} Object containing the encrypted key, initialization vector, and salt
 */
function secureSessionKey(fingerprint, privateKey, deviceID, baseKey) {
    const md = forge.md.sha384.create();
    md.update(deviceID + fingerprint + baseKey);
    const hashedData = md.digest().toHex()
    const salt = forge.random.getBytesSync(32);
    const saltHex = forge.util.bytesToHex(salt);
    const key = forge.pkcs5.pbkdf2(hashedData, salt, 100000, 32, forge.sha256.create());
    const keySliced = key.slice(0, 32);
    let iv = forge.random.getBytesSync(16);
    let ivHex = forge.util.bytesToHex(iv);
    const encryptedPrivatekey = aes_encrypt(privateKey, iv, keySliced);
    return { encryptedKey: encryptedPrivatekey, iv: ivHex, salt: saltHex } ;
}

/**
 * Decrypts a secured private key using the three-factor authentication components
 * 
 * @param {string} encryptedKey - The encrypted key in format "encrypted|iv:salt"
 * @param {string} deviceID - The unique device identifier
 * @param {string} baseKey - The server-provided component of the encryption key
 * @param {string} fingerprint - The browser fingerprint
 * @returns {string} The decrypted private key
 */
async function decryptSecuredKey(encryptedKey, deviceID, baseKey, fingerprint) {
    const md = forge.md.sha384.create();
    md.update(deviceID + fingerprint + baseKey);
    const hashedData = md.digest().toHex()
    const [encrypted, iv] = encryptedKey.split('|');
    const [extractedIv, extractedSalt] = iv.split(':');
    const extractedSaltBytes = forge.util.hexToBytes(extractedSalt);
    const extractedIvBytes = forge.util.hexToBytes(extractedIv);
    const key = forge.pkcs5.pbkdf2(hashedData, extractedSaltBytes, 100000, 32, forge.sha256.create());
    const keySliced = key.slice(0, 32);
    const decrypted = aes_decrypt(encrypted, extractedIvBytes, keySliced);
    console.log('decrypted', decrypted);
    return decrypted;
}

/**
 * Ensures a device ID exists in localStorage, creating one if needed
 * 
 * The device ID is one of the three factors used in the authentication process.
 */
function verifyDeviceID() {
    if (localStorage.getItem('DeviceID') === null) {
        const DeviceID = crypto.randomUUID();
        localStorage.setItem('DeviceID', DeviceID);
    }
}

/**
 * Sets a browser cookie with the specified options
 * 
 * @param {string} name - The name of the cookie
 * @param {string} value - The value to store in the cookie
 * @param {Object} options - Cookie options (path, expires, sameSite, secure)
 */
function setCookie(name, value, options = {}) {
    let cookieString = `${name}=${value}`;
    if (options.path) cookieString += `; path=${options.path}`;
    if (options.expires) cookieString += `; expires=${options.expires.toUTCString()}`;
    if (options.sameSite) cookieString += `; SameSite=${options.sameSite}`;
    if (options.secure) cookieString += `; Secure`;
    document.cookie = cookieString;
}

/**
 * Stores an encrypted private key in IndexedDB
 * 
 * @param {string} key - The encrypted key
 * @param {string} iv - The initialization vector used for encryption
 * @param {string} salt - The salt used for key derivation
 * @returns {Promise<null>} Returns null on error
 */
async function insertKey(key, iv, salt) {
    try {
        const db = await idb.openDB('gluecrypt', 2, {
            upgrade(db, oldVersion, newVersion, transaction) {
                if (!db.objectStoreNames.contains('keys')) {
                    db.createObjectStore('keys');
                }
            }
        });
        const data = key + "|" + iv + ":" + salt;
        await db.put('keys', data, 'privateKey');
    } catch (error) {
        console.error('Failed to save:', error);
        return null;
    }
}

/**
 * Retrieves the encrypted private key from IndexedDB
 * 
 * @returns {Promise<string>} The encrypted key in format "encrypted|iv:salt"
 * @throws {Error} If the key is not found or another error occurs
 */
async function checkAuthKey() {
    try {
        const db = await idb.openDB('gluecrypt', 2, {
            upgrade(db, oldVersion, newVersion, transaction) {
                if (!db.objectStoreNames.contains('keys')) {
                    db.createObjectStore('keys');
                }
            }
        });

        const existingKey = await db.get('keys', 'privateKey');

        if (existingKey !== undefined) {
            return existingKey;
        } else {
            const notfound = document.getElementById('notFoundKey');
            notfound.hidden = false;
            throw new Error('Not found.');
        }
    } catch (error) {
        console.error('Failed to process key:', error);
        throw error;
    }
}

/**
 * Generates an authentication key from a mnemonic phrase
 * 
 * Converts a user-provided mnemonic phrase into a cryptographic key using
 * the BIP-39 standard and HD wallet derivation.
 * 
 * @returns {string} The generated private key
 * @throws {Error} If the mnemonic is invalid or key generation fails
 */
function generateAuthKey() {
    try {
        const authKeyInput = document.getElementById('authkey').value;
        const isValid = validateMnemonic(authKeyInput);
        if (!isValid) {
            alert('Invalid auth key!');
            throw new Error('Invalid auth key');
        }
        const mnemonicKey = authKeyInput.split('-').join(' ');
        const mnemonicObj = ethers.Mnemonic.fromPhrase(mnemonicKey);
        const seed = mnemonicObj.computeSeed();

        const hdNode = ethers.HDNodeWallet.fromSeed(seed);
        return hdNode.privateKey;
    } catch (error) {
        console.error('Failed to generate auth key:', error);
        throw error;
    }
}

/**
 * Encrypts data using AES-CBC algorithm
 * 
 * @param {string} data - The data to encrypt
 * @param {string} iv - The initialization vector
 * @param {string} AESKey - The AES encryption key
 * @returns {string} Base64-encoded encrypted data
 * @throws {Error} If encryption fails
 */
function aes_encrypt(data, iv, AESKey) {
    try {
        let encrypt = forge.cipher.createCipher('AES-CBC', AESKey);
        encrypt.start({ iv: iv });
        encrypt.update(forge.util.createBuffer(data, 'utf-8'));
        encrypt.finish();
        
        let encrypted = forge.util.encode64(encrypt.output.getBytes());
        return encrypted;
    } catch (error) {
        console.error("Encryption error:", error);
        throw error;
    }
}

/**
 * Decrypts data using AES-CBC algorithm
 * 
 * @param {string} encryptedData - Base64-encoded encrypted data
 * @param {string} iv - The initialization vector
 * @param {string} AESKey - The AES decryption key
 * @returns {string} The decrypted data as raw binary
 * @throws {Error} If decryption fails
 */
function aes_decrypt(encryptedData, iv, AESKey) {
    try {
        let decrypt = forge.cipher.createDecipher('AES-CBC', AESKey);
        decrypt.start({ iv: iv });
        decrypt.update(forge.util.createBuffer(forge.util.decode64(encryptedData)));
        decrypt.finish();
        
        // Return raw data instead of assuming UTF-8 encoding
        return decrypt.output.data;
    } catch (error) {
        console.error("Decryption error:", error);
        throw error;
    }
}



/**
 * Main login function implementing Zero-Knowledge Proof authentication
 * 
 * This function performs a secure authentication process with the following steps:
 * 1. Performs key exchange with the server to establish a secure channel
 * 2. Retrieves or generates the authentication key using three-factor authentication
 * 3. Gets a challenge from the server
 * 4. Signs the challenge with the private key
 * 5. Encrypts and sends the authentication data to the server
 * 
 * The authentication flow is designed to ensure the private key is never exposed
 * and can only be used when all three authentication factors are present:
 * - Device ID (something you have)
 * - Browser fingerprint (something you are)
 * - Server-provided baseKey (something you know)
 * 
 * @returns {Promise<void>}
 */
async function login() {
    try {
        let login = document.getElementById('login').value;
        const notfound = document.getElementById('notFoundKey').hidden;
        const DeviceID = localStorage.getItem('DeviceID');
        const fingerprintObj = await getFingerprint();
        const fingerprint = fingerprintObj.thumbmark;
        
        // 1. First perform key exchange to get the baseKey
        console.log('Performing key exchange...');
        let clientPairKeys = ec.genKeyPair();
        let clientPublicKey = clientPairKeys.getPublic('hex');
        
        const keyExchangeResponse = await fetch('http://localhost:3000/api/keyexchange', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                clientPublicKey: clientPublicKey,
            }),
        });

        if (!keyExchangeResponse.ok) {
            throw new Error('HTTPS ERROR: ' + keyExchangeResponse.status);
        }

        const keyData = await keyExchangeResponse.json();
        const serverPublicKey = keyData.serverPublicKey;
        const sessionID = keyData.sessionID;
        const encrypted_baseKey = keyData.baseKey;
        const appBaseIV = keyData.appBaseIV;

        if (!serverPublicKey) {
            throw new Error('Public key not received');
        }

        // Derive shared secret and create AES key
        const serverPublicKeyObj = ec.keyFromPublic(serverPublicKey, 'hex');
        const secret = clientPairKeys.derive(serverPublicKeyObj.getPublic());
        const AESKey = secret.toString('hex').slice(0, 32);
        
        // Decrypt the baseKey
        const baseKey = aes_decrypt(encrypted_baseKey, appBaseIV, AESKey);
        
        // 2. Now prepare the private key (decrypt existing or generate new)
        let authKey;
        if (notfound === true) {
            console.log('Decrypting existing key...');
            const encryptedKey = await checkAuthKey();
            authKey = await decryptSecuredKey(encryptedKey, DeviceID, baseKey, fingerprint);
        } else {
            console.log('Generating new key...');
            authKey = generateAuthKey();
            isGeneratedKey = true;
            
            // Save the new key immediately
            const encrypted_privateKey = secureSessionKey(fingerprint, authKey, DeviceID, baseKey);
            await insertKey(encrypted_privateKey.encryptedKey, encrypted_privateKey.iv, encrypted_privateKey.salt);
        }
        
        // 3. Now get the challenge
        console.log('Getting challenge...');
        const challengeResponse = await fetch("http://localhost:3000/api/auth/getZKPChallenge", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                deviceID: DeviceID,
            })
        });
        
        if (!challengeResponse.ok) {
            const errorData = await challengeResponse.json();
            throw new Error(errorData.error);
        }
        
        const challengeData = await challengeResponse.json();
        const challenge = challengeData.challenge;
        const payload = decodeJwtPayload(challenge);
        const challengeJWT = payload.challenge;
        
        // 4. Sign the challenge with the properly decrypted key
        console.log('Signing challenge...');
        const keyPair = ec.keyFromPrivate(authKey.slice(2));
        const signature = keyPair.sign(challengeJWT);
        const derSignatureHex = signature.toDER('hex');

        // 5. Send authentication data
        console.log('Encrypting data...');
        let iv = forge.random.getBytesSync(16);
        let ivHex = forge.util.bytesToHex(iv);
        let encrypted_login = aes_encrypt(login, ivHex, AESKey);
        let encrypted_challenge = aes_encrypt(derSignatureHex, ivHex, AESKey);
        let encrypted_deviceID = aes_encrypt(DeviceID, ivHex, AESKey);
        let encrypted_jwt = aes_encrypt(challenge, ivHex, AESKey);
        
        // Verify all data was encrypted properly
        if (encrypted_challenge && encrypted_login && encrypted_deviceID && encrypted_jwt) {
            console.log('Successfully encrypted data');
            console.log('Sending data to server...');
        } else {
            throw new Error('Failed to encrypt data..');
        }
        
        // Send authentication request
        const authResponse = await fetch('http://localhost:3000/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                login: encrypted_login,
                challenge: encrypted_challenge,
                deviceID: encrypted_deviceID,
                iv: ivHex,
                jwt: encrypted_jwt,
                sessionID: sessionID
            }),
            credentials: 'include',
            redirect: 'follow'
        });
        
        if (!authResponse.ok) {
            const errorData = await authResponse.json();
            throw new Error(errorData.error);
        }
        
        // Process successful authentication
        const authData = await authResponse.json();
        console.log('Data received from server...');
        console.log('Operation successful');
        
        setCookie("access_token", authData.token, {
            'max-age': 3600,
            'secure': true,
            'samesite': 'strict',
            'path': '/'
        });
        
        window.location.href = "http://localhost:3000/";
    } catch (error) {
        console.error("Login failed:", error);
        alert("Login failed: " + error.message);
    }
}








