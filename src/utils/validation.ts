import validator from 'validator';
import {colors} from "./chalk";

export const ValidateZKP = (login : string) : string => {

    try {
        const forbiddenWords = ['glueeed','glueed','glued', 'glueeeed', 'glue', 'glu','GLUEEED', 'GLUEED', 'GLUED', 'GLU', 'GLUE', " "]

        if (login.trim() === '') {
            return "LoginEmpty";
        }
        if (validator.isEmail(login)) {
            return "InvalidLogin";
        }
        if (login.length < 3 ||  /[!@#$%^&*(),.?":{}|<> ]/.test(login) || forbiddenWords.includes(login) || login.length > 20) {
            return "LoginNotAllowed";
        }
        return "ok";
    } catch (e) {
        console.group(colors.category('Validation Service'))
        console.error(colors.error(e));
        return 'Error';
    }


}