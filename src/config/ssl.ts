import fs from 'fs';
import path from 'path';

 export const options : object = {
    key: fs.readFileSync("/your/path/key"),
    cert: fs.readFileSync("/your/path/cert"),
    ca: fs.readFileSync("/your/path/chain"),
};