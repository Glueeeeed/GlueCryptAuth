import * as forge from 'node-forge';


export function data_decrypt(data: string, iv: string, secretkey: string): string {

    const encryptedBytes = forge.util.decode64(data);

    const decrypt = forge.cipher.createDecipher('AES-CBC', secretkey);

    decrypt.start({ iv: forge.util.createBuffer(iv) });

    decrypt.update(forge.util.createBuffer(encryptedBytes));

    const success = decrypt.finish();

    if (success) {
        return decrypt.output.toString();
    } else {
        throw new Error('Decryption Failed');
    }
}

export function data_encrypt(data: string, iv: string, secretkey: string): string {
    
    const encrypt = forge.cipher.createCipher('AES-CBC', secretkey);
    
    encrypt.start({ iv: forge.util.createBuffer(iv) });
    
    encrypt.update(forge.util.createBuffer(data));
    
    const success = encrypt.finish();
    
    if (success) {
        return forge.util.encode64(encrypt.output.data);
    } else {
        throw new Error('Encryption Failed');
    }
}

