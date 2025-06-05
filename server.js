const express = require('express');
const cookieParser = require('cookie-parser');
const csrf = require('csrf');
const dotenv = require('dotenv');
const crypto = require('crypto');
const cors = require('cors');

dotenv.config();

const port = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'secret';

// Función para hacer hashing SHA-256
function hash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// Usuario con hash de contraseña (admin)
const users = [
    {
        username: hash('admin'),
        password: hash('admin')
    }
];

const sessions = {};

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: 'http://localhost:3001', // corregido
    credentials: true
}));

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.get('/csrf-token', (req, res) => {
    const csrfToken = new csrf().create(SECRET_KEY);
    res.json({ csrfToken });
});

app.post('/login', (req, res) => {
    const { username, password, csrfToken } = req.body;

    if (!csrf().verify(SECRET_KEY, csrfToken)) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña son requeridos.' });
    }

    const hashedUsername = hash(username);
    const hashedPassword = hash(password);

    const user = users.find(user => user.username === hashedUsername);

    if (!user || user.password !== hashedPassword) {
        return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
    }

    const sessionId = crypto.randomBytes(16).toString('base64url');
    sessions[sessionId] = { username: hashedUsername };
    res.cookie('sessionId', sessionId, {
        httpOnly: true,
        secure: false, // cambia a true si usas HTTPS
        sameSite: 'lax'
    });

    res.status(200).json({ message: 'Login successful' });
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
