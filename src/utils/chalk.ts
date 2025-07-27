import chalk from 'chalk';

export interface ThemeColors {
    error: typeof chalk;
    warning: typeof chalk;
    success: typeof chalk;
    info: typeof chalk;
    category: typeof chalk;
}

export const colors: ThemeColors = {
    category: chalk.hex('#5232a8'),
    error: chalk.hex('#db1414'),
    warning: chalk.hex('#faad14'),
    success: chalk.hex('#52c41a'),
    info: chalk.hex('#1890ff'),
};