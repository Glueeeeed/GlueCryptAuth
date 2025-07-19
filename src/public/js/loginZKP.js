let ec = new elliptic.ec('p256');
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
        alert('Key reset successfully!');
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


async function insertKey(key) {
    try {
        const db = await idb.openDB('gluecrypt', 2, {
            upgrade(db, oldVersion, newVersion, transaction) {
                if (!db.objectStoreNames.contains('keys')) {
                    db.createObjectStore('keys');
                }
            }
        });
        await db.put('keys', key, 'privateKey');
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
            console.log(existingKey);
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
        console.log(hdNode.privateKey);
        return hdNode.privateKey;


    } catch (error) {
        console.error('Failed to generate auth key:', error);
        throw error;
    }
}



async function  login() {
    let login = document.getElementById('login').value;
    const notfound = document.getElementById('notFoundKey').hidden;
    if (notfound === true) {
        const authKey = await checkAuthKey();
        console.log('Generating challenge...')
        const DeviceID = localStorage.getItem('DeviceID');
        fetch("http://localhost:3000/api/auth/getZKPChallenge", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                deviceID: DeviceID,
            })
        })
            .then((response) => {
                if (!response.ok) {
                    return response.json().then((errorData) => {
                        throw new Error(errorData.error);
                    });
                }
                return response.json();
            })
            .then((data) => {
                const challenge = data.challenge;
                const payload = decodeJwtPayload(challenge);
                const challengeJWT = payload.challenge;
                console.log(challengeJWT);
                const keyPair = ec.keyFromPrivate(authKey.slice(2));
                const signature = keyPair.sign(challengeJWT);
                const derSignatureHex = signature.toDER('hex');
                console.log('Signature: ', derSignatureHex);
                authenticate(derSignatureHex, challenge, DeviceID, login);
            })




    } else {
        console.log('Generating key.');
        const authKey = generateAuthKey();
        console.log('Inserted');
        await insertKey(authKey);
        console.log('Generating challenge...')
        const DeviceID = localStorage.getItem('DeviceID');
        fetch("http://localhost:3000/api/auth/getZKPChallenge", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                deviceID: DeviceID,
            })
        })
            .then((response) => {
                if (!response.ok) {
                    return response.json().then((errorData) => {
                        throw new Error(errorData.error);
                    });
                }
                return response.json();
            })
            .then((data) => {
                const challenge = data.challenge;
                const payload = decodeJwtPayload(challenge);
                const challengeJWT = payload.challenge;
                console.log(challengeJWT);
                const keyPair = ec.keyFromPrivate(authKey.slice(2));
                const signature = keyPair.sign(challengeJWT);
                const derSignatureHex = signature.toDER('hex');
                console.log('Signature: ', derSignatureHex);
                authenticate(derSignatureHex, challenge, DeviceID, login);
            })


    }
}


async function  authenticate(Signed_challenge, jwt ,deviceID, loginUser) {
    let clientPairKeys = ec.genKeyPair();
    let clientPublicKey = clientPairKeys.getPublic('hex');
    fetch('http://localhost:3000/api/keyexchange', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            clientPublicKey: clientPublicKey,
        }),
    })
        .then((response) => {
            if (!response.ok) throw new Error('HTTPS ERROR: ' + response.status);
            return response.json();
        })
        .then((data) => {
            const serverPublicKey = data.serverPublicKey;
            const sessionID = data.sessionID;
            if (!serverPublicKey) {
                throw new Error('Public key not received');
            }

            const serverPublicKeyObj = ec.keyFromPublic(serverPublicKey, 'hex');
            const secret = clientPairKeys.derive(serverPublicKeyObj.getPublic());
            const AESKey = secret.toString('hex').slice(0, 32);



            function aes_encrypt(data, iv) {
                let encrypt = forge.cipher.createCipher('AES-CBC', AESKey);
                encrypt.start({ iv: iv });
                encrypt.update(forge.util.createBuffer(data, 'utf-8'));
                encrypt.finish();


                let encrypted = forge.util.encode64(encrypt.output.getBytes());

                return encrypted;
            }

            console.log('Encrypting data...')
            let iv = forge.random.getBytesSync(16);
            let ivHex = forge.util.bytesToHex(iv);
            let encrypted_login = aes_encrypt(loginUser, ivHex);
            let encrypted_challenge = aes_encrypt(Signed_challenge, ivHex);
            let encrypted_deviceID = aes_encrypt(deviceID, ivHex);
            let encrypted_jwt = aes_encrypt(jwt, ivHex);

            if (encrypted_challenge || encrypted_login || encrypted_deviceID) {
                console.log('Successfully encrypted data');
                console.log('Sending data to server...');
            } else {
                throw new Error('Failed to encrypt data..');
            }

            fetch('http://localhost:3000/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    login: encrypted_login,
                    challenge: encrypted_challenge,
                    deviceID: encrypted_deviceID,
                    iv:ivHex,
                    jwt: encrypted_jwt,
                    sessionID: sessionID
                }),
                credentials: 'include',
                redirect: 'follow'
            }).then((response) => {
                if (!response.ok) {
                    return response.json().then((errorData) => {
                        throw new Error(errorData.error);
                    });
                }
                return response.json();
            })
                .then((data) => {
                    console.log('Data received from server...');
                    console.log('Operation successful');
                    setCookie("access_token", data.token, {
                        'max-age': 3600,
                        'secure': true,
                        'samesite': 'strict',
                        'path': '/'
                    });
                    window.location.href = "http://localhost:3000/";

                })
                .catch((error) => {
                    console.log(`Operation failed: ${error.message}`);
                    alert("Failed Login: " + error.message);
                });







        })
}





