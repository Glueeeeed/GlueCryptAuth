// MIT License
//
// Copyright (c) 2025 Glueeed
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
//     The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
//     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//     OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import express, { Request, Response } from 'express';
import path from "path";
import cookieParser from 'cookie-parser';
import cors from 'cors';
import https from 'https';
import helmet from 'helmet';
import {colors} from "./utils/chalk";

//Uncomment when httpsMode is enabled
// import {options} from "./config/ssl";
// import {corsEnabled, httpsMode, PORT, domain, helmetEnabled, helmetConfig} from "./config/settings"; //Uncomment when helmet is enabled
import {corsEnabled, httpsMode, PORT, domain, helmetEnabled} from "./config/settings"; //Comment when helmet is enabled

// Import Routes
import keyEnchange from "./routes/keyEnchange";
import auth from "./routes/auth";
import {secured} from "./ middlewares/auth";


const app = express();
const port : number = PORT


//Uncomment when httpsMode is enabled

// const ssl = options


//Middlewares
app.use(express.json());
app.use(cookieParser());

if (corsEnabled === true) {
    const corsOptions = {
        origin: domain,
        credentials: true,
        optionsSuccessStatus: 200,
    };
    app.use(cors());
}

// if (helmetEnabled === true) {
//     // app.use(helmet(helmetConfig)); //Uncomment when helmet is enabled
// }


// Frontend handling

app.use(express.static(path.join(__dirname, 'public')));

app.get('/register', (req: Request, res: Response)  => {
    res.sendFile(path.join(__dirname, 'public', '/views' ,'register.html'));
})

app.get('/login', (req: Request, res: Response)  => {
    res.sendFile(path.join(__dirname, 'public', '/views' ,'login.html'));
})

// API endpoints

app.use('/api', keyEnchange);
app.use('/api/auth', auth);

app.get('/', secured, (req: Request, res: Response) => {
    res.send('Sybau!');
});





if (httpsMode === true) {
    console.group(colors.category('Core App'))
    // https.createServer(ssl, app).listen(port, "0.0.0.0", () => {
    //
    //     console.log(colors.info(`App running at glueeed.dev:${port}`));
    //
    // });
    console.groupEnd()

} else {
    console.group(colors.category('Core App'))
    app.listen(port, () => {
        console.log(colors.info(`App running at http://localhost:${port}`));

    });
    console.groupEnd()

}




