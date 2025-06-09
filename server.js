const express = require('express');
const cookieParser = require('cookie-parser');
const csrf = require('csrf');
const dotenv = require('dotenv');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cors = require('cors');

dotenv.config();

const port = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'secret';

const users = []; // almacenará { username, passwordHash }
const sessions = {};

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: 'http://localhost:3001',
    credentials: true
}));

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.get('/csrf-token', (req, res) => {
    const csrfToken = new csrf().create(SECRET_KEY);
    res.json({ csrfToken });
});

// ✅ Nuevo: registro
app.post('/register', async (req, res) => {
    const { username, password, csrfToken } = req.body;

    if (!csrf().verify(SECRET_KEY, csrfToken)) {
        return res.status(403).json({ error: 'CSRF token inválido' });
    }

    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    }

    const existing = users.find(u => u.username === username);
    if (existing) {
        return res.status(409).json({ error: 'Usuario ya registrado' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    users.push({ username, passwordHash });
    res.status(201).json({ message: 'Usuario registrado con éxito' });
});

// 🔐 Login con bcrypt
app.post('/login', async (req, res) => {
    const { username, password, csrfToken } = req.body;

    if (!csrf().verify(SECRET_KEY, csrfToken)) {
        return res.status(403).json({ error: 'CSRF token inválido' });
    }

    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    }

    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    const passwordOk = await bcrypt.compare(password, user.passwordHash);
    if (!passwordOk) {
        return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    const sessionId = crypto.randomBytes(16).toString('base64url');
    sessions[sessionId] = { username };
    res.cookie('sessionId', sessionId, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax'
    });

    res.status(200).json({ message: 'Login exitoso' });
});

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
