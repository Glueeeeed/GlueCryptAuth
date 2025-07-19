import fs from 'fs';
import path from 'path';

 export const options : object = {
    key: fs.readFileSync("/etc/letsencrypt/live/glueeed.dev/privkey.pem"),
    cert: fs.readFileSync("/etc/letsencrypt/live/glueeed.dev/cert.pem"),
    ca: fs.readFileSync("/etc/letsencrypt/live/glueeed.dev/chain.pem"),
};