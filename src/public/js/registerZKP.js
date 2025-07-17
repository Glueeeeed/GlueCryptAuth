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


function generateAuthKeys() {
    const bipkey = document.getElementById('bipkey');

    const mnemonic = ethers.Mnemonic.fromEntropy(ethers.randomBytes(24));
    const mnemonicFormatted = mnemonic.phrase.split(' ').join('-');
    bipkey.textContent = mnemonicFormatted;


    const mnemonicObj = ethers.Mnemonic.fromPhrase(mnemonic.phrase);
    const seed = mnemonicObj.computeSeed();


    const hdNode = ethers.HDNodeWallet.fromSeed(seed);
    const privateKey = hdNode.privateKey;


    const ec = new elliptic.ec('p256');
    const keyPair = ec.keyFromPrivate(privateKey.slice(2));
    const publicKey = keyPair.getPublic('hex');

    return { publicKey: publicKey, privateKey: privateKey };
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


function  register() {
    let login = document.getElementById('login').value;

    let clientPairKeys = ec.genKeyPair();
    let clientPublicKey = clientPairKeys.getPublic('hex');
    const keys = generateAuthKeys();
    const registered = document.getElementById('registered');
    registered.hidden = false;
    insertKey(keys.privateKey);







    fetch('https://glueeeed.pl:3000/api/keyexchange', {
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
            let encrypted_login = aes_encrypt(login, ivHex);
            let encrypted_publicKey = aes_encrypt(keys.publicKey, ivHex);

            if (encrypted_publicKey || encrypted_login) {
                console.log('Successfully encrypted data');
                console.log('Sending data to server...');
            } else {
                throw new Error('Failed to encrypt data..');
            }




            fetch("https://glueeeed.dev:3000/api/auth/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    login: encrypted_login,
                    publickey: encrypted_publicKey,
                    iv: ivHex,
                    sessionID: sessionID
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
                    console.log('Data received from server...');
                    console.log('Operation successful');
                    // const registered = document.getElementById('registered');
                    // registered.hidden = false;
                    // insertKey(keys.privateKey);

                })
                .catch((error) => {
                    console.log(`Operation failed: ${error.message}`);
                    alert("Failed Register: " + error.message);
                });







        })
}