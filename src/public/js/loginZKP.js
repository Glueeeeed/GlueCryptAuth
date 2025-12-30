/**
 * GlueCryptAuth - Secure Authentication System
 *
 * This module handles the secure login process using elliptic curve cryptography,
 * digital signatures inspired by zero-knowledge principles, and multi-factor
 * authentication with device fingerprinting.
 */



let ec = new elliptic.ec('p256');

let isGeneratedKey = false;


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
        console.log('Deleted keys from DB');
    } catch (error) {
        console.error('Failed to save:', error);
        return null;
    }
}



function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(str);
    try {
        return decodeURIComponent(escape(decoded));
    } catch {
        return decoded;
    }
}


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



function decodeJwtPayload(token) {
    const payloadBase64Url = token.split('.')[1];
    if (!payloadBase64Url) throw new Error('Invalid token');
    return JSON.parse(base64UrlDecode(payloadBase64Url));
}



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

    // Key format verification
    if (typeof encryptedKey !== 'string' || !encryptedKey.includes('|') || !encryptedKey.includes(':')) {
        resetKey();
        throw new Error("Authentication key is corrupted. Key has been removed! You must add it again");
    }

    const [encrypted, iv] = encryptedKey.split('|');

    if (!iv || !iv.includes(':')) {
        resetKey();
        throw new Error("Authentication key is corrupted. Key has been removed! You must add it again");
    }

    const [extractedIv, extractedSalt] = iv.split(':');

    if (!extractedIv || !extractedSalt) {
        resetKey();
        throw new Error("Authentication key is corrupted. Key has been removed! You must add it again");
    }

    const extractedSaltBytes = forge.util.hexToBytes(extractedSalt);
    const extractedIvBytes = forge.util.hexToBytes(extractedIv);
    const key = forge.pkcs5.pbkdf2(hashedData, extractedSaltBytes, 100000, 32, forge.sha256.create());
    const keySliced = key.slice(0, 32);
    const decrypted = aes_decrypt(encrypted, extractedIvBytes, keySliced);
    return decrypted;
}




function verifyDeviceID() {
    if (localStorage.getItem('DeviceID') === null) {
        const DeviceID = crypto.randomUUID();
        localStorage.setItem('DeviceID', DeviceID);
    }
}


function setCookie(name, value, options = {}) {
    let cookieString = `${name}=${value}`;
    if (options.path) cookieString += `; path=${options.path}`;
    if (options.expires) cookieString += `; expires=${options.expires.toUTCString()}`;
    if (options.sameSite) cookieString += `; SameSite=${options.sameSite}`;
    if (options.secure) cookieString += `; Secure`;
    document.cookie = cookieString;
}




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
            throw new Error('Authentication key has not found.');
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



function aes_encrypt(data, iv, AESKey) {
    try {
        let gcmIv = iv;
        if (iv.length > 12) {
            gcmIv = iv.substring(0, 12);
        }

        let encrypt = forge.cipher.createCipher('AES-GCM', AESKey);
        encrypt.start({
            iv: gcmIv,
            tagLength: 128
        });
        encrypt.update(forge.util.createBuffer(data, 'utf-8'));
        encrypt.finish();

        const encryptedData =  encrypt.mode.tag.getBytes() + encrypt.output.getBytes()
        return forge.util.encode64(encryptedData);
    } catch (error) {
        console.error("Encryption error:", error);
        throw error;
    }
}



function aes_decrypt(encryptedData, iv, AESKey) {
    try {
        let gcmIv = iv;
        if (iv.length > 12) {
            gcmIv = iv.substring(0, 12);
        }

        const encryptedBytes = forge.util.decode64(encryptedData);

        const tag = encryptedBytes.slice(0,16);
        const bytes = encryptedBytes.slice(16, encryptedBytes.length);

        let decrypt = forge.cipher.createDecipher('AES-GCM', AESKey);
        decrypt.start({
            iv: gcmIv,
            tag: forge.util.createBuffer(tag),
            tagLength: 128
        });
        decrypt.update(forge.util.createBuffer(bytes));

        const pass = decrypt.finish();
        if (!pass) {
            resetKey();
            throw new Error("Authentication key is corrupted. Key has been removed! You must add it again");
        }

        return decrypt.output.data;
    } catch (error) {
        console.error("Decryption error:", error);
        throw error;
    }
}



/**
 * Main login function
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
        // Validate user input
        const login = document.getElementById('login').value;
        if (!login || login.trim() === "") {
            throw new Error("User ID cannot be empty");
        }
        const notfound = document.getElementById('notFoundKey').hidden;
        const DeviceID = localStorage.getItem('DeviceID');
        const fingerprintObj = await getFingerprint();
        const fingerprint = fingerprintObj.thumbmark;

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


        const serverPublicKeyObj = ec.keyFromPublic(serverPublicKey, 'hex');
        const secret = clientPairKeys.derive(serverPublicKeyObj.getPublic());
        const AESKey = secret.toString('hex').slice(0, 32);


        const baseKey = aes_decrypt(encrypted_baseKey, appBaseIV, AESKey);

        let authKey;
        if (notfound === true) {
            console.log('Decrypting existing key...');
            const encryptedKey = await checkAuthKey();
            authKey = await decryptSecuredKey(encryptedKey, DeviceID, baseKey, fingerprint);
        } else {
            console.log('Generating new key...');
            authKey = generateAuthKey();
            isGeneratedKey = true;

            const encrypted_privateKey = secureSessionKey(fingerprint, authKey, DeviceID, baseKey);
            await insertKey(encrypted_privateKey.encryptedKey, encrypted_privateKey.iv, encrypted_privateKey.salt);
        }


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

        console.log('Signing challenge...');
        const keyPair = ec.keyFromPrivate(authKey.slice(2));
        const signature = keyPair.sign(challengeJWT);
        const derSignatureHex = signature.toDER('hex');

        console.log('Encrypting data...');
        let iv = forge.random.getBytesSync(16);
        let ivHex = forge.util.bytesToHex(iv);
        let encrypted_login = aes_encrypt(login, ivHex, AESKey);
        let encrypted_challenge = aes_encrypt(derSignatureHex, ivHex, AESKey);
        let encrypted_deviceID = aes_encrypt(DeviceID, ivHex, AESKey);
        let encrypted_jwt = aes_encrypt(challenge, ivHex, AESKey);

        if (encrypted_challenge && encrypted_login && encrypted_deviceID && encrypted_jwt) {
            console.log('Successfully encrypted data');
            console.log('Sending data to server...');
        } else {
            throw new Error('Failed to encrypt data..');
        }

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

        const authData = await authResponse.json();
        console.log('Data received from server...');
        console.log('Operation successful');

        setCookie("access_token", authData.token, {
            'max-age': 3600,
            'secure': true,
            'samesite': 'strict',
            'path': '/'
        });

        window.location.href = `http://localhost:3000/`;
    } catch (error) {
        console.error("Login failed:", error);
        alert("Login failed: " + error.message);
    }
}








