import * as crypto from 'crypto';

export const generateSecrets= () : object => {
    console.log("Generating Secrets..");
    let secrets: Map<string, string> = new Map();
    for (let i: number = 0; i < 3; i++) {
        secrets.set('Secret ' + String(i), crypto.randomBytes(512).toString('hex'))
    }

    return secrets;


}

console.log(generateSecrets());