import 'dotenv/config';
import { HelmetOptions } from 'helmet';


// If is true, connection using https. Check ssl.ts to fill ssl certificate.
export const httpsMode : boolean = false;
//Allow to log in only Admins
export const onlyAdmin : boolean = false;
// Block register new accounts
export const disabled : boolean = false;
// Enter your domain (If locally type http://localhost)
export const domain : string = "https://glueeed.dev";
//Runs application on the selected port
export const PORT : number = 3000;
// If is true, CORS is enabled
export const corsEnabled : boolean = true;
// If is true, helmet is enabled
export const helmetEnabled : boolean = true;

// Helmet configuration
export const helmetConfig: HelmetOptions = {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'sha256-Fcgm+CT4OSBQ3uXaCWZnbIeUkWcIIYemt071st0N5NI='"],
            scriptSrcAttr: ["'unsafe-hashes'","'sha256-Fcgm+CT4OSBQ3uXaCWZnbIeUkWcIIYemt071st0N5NI='", "'sha256-DIm7WJS6ZKDYe5qFLPy+h4JFI9Bol5QmYC57mt3Fb00='", "'sha256-jWtubtNanrD5ZxqOMi+Ci/WbpkARGhF/hlyM1x5ZbNY='", "'sha256-k+TLT/+AXgEDXNzRKraEyUBN9qUb4BTyQnPrx8I5jiM='", "'sha256-OXqjjmv8hsJ7lR+n3ceuDu6KBNh8WlE7+5+vLocG1f4='", "'sha256-b989YQRv44kuqwBnQvfcsnS74tS/X2F8g4+EMqjCVIk='", "'sha256-oVgFalMB66j+xkvSyZzDgre7h/qer4QsJOFbmaC1ZBk='", "'sha256-6OUjnaW3cNsM7aWVVdK78pdyibrtZFEaG/UohwTRouk='", "'sha256-6YrdAr6O2pO23e1+71GR25aY/8ykeI0iNu6nOr3W0Y8='", "'sha256-Cfm6jhezwRRuVzR/VMwr//Wof7h8RsylsQf8C+mkkLo='", "'sha256-DRq5oY5RL/iABTJ0KXfclQfNm2lTo79duP1TVz878FE='"], //Hashes for inline event handlers
            styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com", "cdnjs.cloudflare.com", "fonts.gstatic.com"],
            fontSrc: ["'self'", "fonts.gstatic.com", "data:", "fonts.googleapis.com", "cdnjs.cloudflare.com", "fonts.gstatic.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "https://glueeed.dev:6969", "http://localhost:3000"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            workerSrc: ["'self'", "blob:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    },
    referrerPolicy: {
        policy: 'strict-origin-when-cross-origin' as const,
    },
    xFrameOptions: { action: 'deny' },
    xContentTypeOptions: true,
};

