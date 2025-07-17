import validator from 'validator';

export const ValidateZKP = (login : string) : string => {

    const forbiddenWords = ['glueeed','glueed','glued', 'glueeeed', 'glue', 'glu','GLUEEED', 'GLUEED', 'GLUED', 'GLU', 'GLUE']

    if (login.trim() === '') {
        return "LoginEmpty";
    }
    if (validator.isEmail(login)) {
        return "InvalidLogin";
    }
    if (
        login.length < 3 ||  /[!@#$%^&*(),.?":{}|<>]/.test(login) || forbiddenWords.includes(login)) {
        return "LoginNotAllowed";
    }
    return "ok";
}