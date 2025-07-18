# GlueCryptAuth

A TypeScript-based authentication system that leverages mnemonic phrases and cryptographic signatures for secure, privacy-focused user login. Part of the **Gluecrypt** **(SOON)** ecosystem, GlueCryptAuth provides a robust and modern approach to authentication without relying on traditional passwords.

## Features
- **Mnemonic-based Key Generation**: Users generate a private-public key pair from a mnemonic phrase during registration.
- **Secure Storage**: Private keys are stored locally in IndexedDB, ensuring user control over sensitive data.
- **Cryptographic Signatures**: Authentication is performed by signing server-issued challenges with the user's private key.
- **Privacy-First**: User IDs are random and non-sensitive, protecting personal information.
- **TypeScript Implementation**: Written in TypeScript for type safety and maintainability.

## Installation and Running (locally or online)

1. Clone the repository:

   ```bash
   git clone https://github.com/Glueeeeed/GlueCryptAuth.git
2. Install dependencies:
    ``` bash
    npm install
   ```
3. Configure the MySQL database:
    - Create a database named `gluecrypt_auth_db`.
    - Create the `usersZKP` table.
      


  4. SQL CODE:
      ```sql
        CREATE DATABASE gluecrypt_auth_db;
      
        USE gluecrypt_auth_db;
      
        CREATE TABLE usersZKP (
         usersID INT AUTO_INCREMENT PRIMARY KEY,
         login TEXT NOT NULL,
         publickey TEXT NOT NULL,
         admin BOOLEAN,
         uuid TEXT NOT NULL );
   
5. Create `secrets.ts` (Check `example.secrets.ts`)
6. Start the application:

   ``` bash
   npm run
   ```
7. Open your browser and go to `http://localhost/register` or `https://yourdomain/register`

## Usage
1. **Registration**:
    - User provides a random userID.
    - A mnemonic phrase is generated, from which a private-public key pair is derived.
    - The public key and userID are sent to the server, while the private key is stored in IndexedDB.
    - The mnemonic phrase is displayed for the user to back up securely.
2. **Login**:
    - User enters their userID.
    - If the private key exists in IndexedDB, it is used to sign a server-issued challenge.
    - If not, the user inputs their mnemonic phrase to regenerate the private key, which is then stored in IndexedDB.
    - The server verifies the signed challenge to authenticate the user.

## Motivation
Inspired by Zero-Knowledge Proof concepts, GlueCryptAuth provides a secure and user-friendly authentication system that avoids traditional password vulnerabilities while leveraging cryptographic signatures and mnemonic phrases.

## Warning

This project is still in development and is not yet complete. It is **not suitable for production use** at this time. Use it at your own risk, as it may contain bugs or incomplete features.


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
