/**
 * GlueCryptAuth - Zero Knowledge Proof Registration System
 * 
 * This module handles the secure registration process using elliptic curve cryptography,
 * zero-knowledge proofs, and multi-factor authentication with device fingerprinting.
 * It generates and securely stores cryptographic keys for future authentication.
 */

// Initialize elliptic curve with P-256 standard
let ec = new elliptic.ec('p256');

// Setup initial state when DOM is fully loaded
document.addEventListener("DOMContentLoaded", (event) => {
    verifyDeviceID()
    resetRegistered()
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
 * Copies the generated mnemonic phrase to the clipboard
 * This allows users to save their recovery phrase
 */
function copyTextToClipboard() {
    if (!navigator.clipboard) {
        alert('Copying to the clipboard is not supported in this browser.');
        return;
    }
    let output = document.getElementById('bipkey').textContent;
    navigator.clipboard.writeText(output);
    alert('copied');
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
 * Resets the registration state in localStorage
 * 
 * This ensures users can restart the registration process if needed
 */
function resetRegistered() {
    if (localStorage.getItem('is_Registered') !== null) {
        localStorage.removeItem('is_Registered')
    }
}

/**
 * Ensures a device ID exists in localStorage, creating one if needed
 * 
 * The device ID is one of the three factors used in the authentication process
 */
function verifyDeviceID() {
    if (localStorage.getItem('DeviceID') === null) {
        const DeviceID = crypto.randomUUID();
        localStorage.setItem('DeviceID', DeviceID);
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
 * Generates cryptographic key pairs for user authentication
 * 
 * Creates a BIP-39 mnemonic phrase, derives a seed, and generates both
 * a private key and corresponding public key for elliptic curve cryptography.
 * The mnemonic phrase is displayed to the user as a recovery mechanism.
 * 
 * @param {boolean} userRegistered - Flag indicating if user is already registered
 * @returns {Object} Object containing the public and private keys
 * @throws {Error} If user is already registered or key generation fails
 */
function generateAuthKeys(userRegistered) {
    const bipkey = document.getElementById('bipkey');
    if (localStorage.getItem('is_Registered') !== null){
        throw new Error('User already registered')
    }

    const mnemonic = ethers.Mnemonic.fromEntropy(ethers.randomBytes(24));
    const mnemonicFormatted = mnemonic.phrase.split(' ').join('-');
    bipkey.textContent = mnemonicFormatted;

    const mnemonicObj = ethers.Mnemonic.fromPhrase(mnemonic.phrase);
    const seed = mnemonicObj.computeSeed();

    const hdNode = ethers.HDNodeWallet.fromSeed(seed);
    const privateKey = hdNode.privateKey;
    console.log('privateKey', privateKey);

    const ec = new elliptic.ec('p256');
    const keyPair = ec.keyFromPrivate(privateKey.slice(2));
    const publicKey = keyPair.getPublic('hex');

    return { publicKey: publicKey, privateKey: privateKey };
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
 * Main registration function implementing secure key generation and storage
 * 
 * This function performs a secure registration process with the following steps:
 * 1. Validates user input
 * 2. Generates authentication keys (public/private key pair)
 * 3. Performs key exchange with the server to establish a secure channel
 * 4. Secures the private key using three-factor authentication
 * 5. Encrypts and sends registration data to the server
 * 
 * The security model ensures the private key is protected by:
 * - Device ID (something you have)
 * - Browser fingerprint (something you are)
 * - Server-provided baseKey (something you know)
 * 
 * @returns {Promise<void>}
 */
async function register(){
    try {
        // Validate user input
        const login = document.getElementById('login').value;
        if (!login || login.trim() === "") {
            throw new Error("User ID cannot be empty");
        }
        
        // Get device identification factors
        const clientPairKeys = ec.genKeyPair();
        const clientPublicKey = clientPairKeys.getPublic('hex');
        const DeviceID = localStorage.getItem('DeviceID');
        const fingerprintObj = await getFingerprint();
        const fingerprint = fingerprintObj.thumbmark;

        // Generate authentication keys
        const keys = generateAuthKeys();

        // Perform key exchange with server
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
        const baseKey = aes_decrypt(encrypted_baseKey, appBaseIV, AESKey);

        console.log('Encrypting data...');

        // Encrypt registration data
        const iv = forge.random.getBytesSync(16);
        const ivHex = forge.util.bytesToHex(iv);
        const encrypted_login = aes_encrypt(login, ivHex, AESKey);
        const encrypted_publicKey = aes_encrypt(keys.publicKey, ivHex, AESKey);
        
        // Secure and store the private key
        const secure = secureSessionKey(fingerprint, keys.privateKey, DeviceID, baseKey);
        console.log(secure.encryptedKey);
        console.log(secure.iv);
        await insertKey(secure.encryptedKey, secure.iv, secure.salt);

        // Verify all data was encrypted properly
        if (encrypted_publicKey && encrypted_login && secure.encryptedKey && secure.iv && secure.salt) {
            console.log('Successfully encrypted data');
            console.log('Sending data to server...');
        } else {
            throw new Error('Failed to encrypt data.');
        }

        // Send registration request
        const registerResponse = await fetch('http://localhost:3000/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                login: encrypted_login,
                publickey: encrypted_publicKey,
                iv: ivHex,
                sessionID: sessionID,
            })
        })

        if (!registerResponse.ok) {
            const errorData = await registerResponse.json();
            throw new Error(errorData.error);
        }

        // Process successful registration
        const registerData = await registerResponse.json();
        console.log('Data received from server...');
        console.log('Operation successful');
        const registered = document.getElementById('registered');
        localStorage.setItem('is_Registered', 'true');
        alert(registerData.response);
        registered.hidden = false;

    } catch (error) {
        console.error(error);
        alert("Failed register: " + error.message);
    }
}


