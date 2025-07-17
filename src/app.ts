
import express, { Request, Response } from 'express';
import path from "path";

// Import Routes
import keyEnchange from "./routes/keyEnchange";
import auth from "./routes/auth";


const app = express();
const port = 3000;

app.use(express.json());

// Frontend handling

app.use(express.static(path.join(__dirname, 'public')));

app.get('/register', (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', '/views' ,'register.html'));
})

// API endpoints

app.use('/api', keyEnchange);
app.use('/api/auth', auth)

app.get('/', (req: Request, res: Response) => {
    res.send('Hello, TypeScript Express!');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});