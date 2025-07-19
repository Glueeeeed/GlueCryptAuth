import 'dotenv/config';
import { HelmetOptions } from 'helmet';


// If is true, connection using https. Check ssl.ts to fill ssl certificate.
export const httpsMode : boolean = false;
//Allow to log in only Admins
export const onlyAdmin : boolean = false;
// Block register new accounts
export const disabled : boolean = false;
// Enter your domain (If locally type http://localhost)
export const domain : string = "http://localhost";
//Runs application on the selected port
export const PORT : number = 3000;
// If is true, CORS is enabled
export const corsEnabled : boolean = false;
// If is true, helmet is enabled
export const helmetEnabled : boolean = false;

// Helmet configuration
export const helmetConfig: HelmetOptions = {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", 'https://glueeed.dev'],
            styleSrc: ["'self'", 'https://glueeed.dev'],
            connectSrc: ["'self'", 'https://glueeed.dev', 'http://localhost:3000'], // Allow API requests
            imgSrc: ["'self'", 'data:'],
            frameSrc: ["'none'"], // Prevent framing
            objectSrc: ["'none'"], // Prevent plugins
            baseUri: ["'self'"],
            formAction: ["'self'"],
        },
    },
    hsts: {
        maxAge: 31536000, // 1 year in seconds
        includeSubDomains: true,
        preload: true,
    },
    referrerPolicy: {
        policy: 'strict-origin-when-cross-origin' as const,
    },
    xFrameOptions: { action: 'deny' },
    xContentTypeOptions: true, // Enable nosniff
};

