import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import 'dotenv/config';

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const PORT = process.env.PORT || 3000;

app.use(express.json());

let users = [
    { id: 1, username: 'user1', email: 'user1@example.com', password: bcrypt.hashSync('qwerty', 10), role: 'user' },
    { id: 2, username: 'admin', email: 'admin@example.com', password: bcrypt.hashSync('qwerty', 10), role: 'admin' }
];

function authorizeRole(req, res, next) {
    const user = users.find(u => u.id === req.user.id);
    if (user && user.role === 'admin') {
        next();
    } else {
        res.sendStatus(403);
    }
}

function authenticateJWT(req, res, next) {
    const token = req.header('Authorization') && req.header('Authorization').split(' ')[1];
    if (!token) return res.sendStatus(403);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.sendStatus(403);
    }
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
    res.json({ token });
});

app.put('/update-email', authenticateJWT, (req, res) => {
    const { newEmail } = req.body;
    const user = users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    user.email = newEmail;
    res.json({ message: 'Email updated successfully', user });
});

app.put('/update-role', authenticateJWT, authorizeRole, (req, res) => {
    const { userId, newRole } = req.body;
    const user = users.find(u => u.id === userId);
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    user.role = newRole;
    res.json({ message: 'Role updated successfully', user });
});

app.delete('/delete-account', authenticateJWT, (req, res) => {
    const userIndex = users.findIndex(u => u.id === req.user.id);
    if (userIndex === -1) {
        return res.status(404).json({ message: 'User not found' });
    }
    users.splice(userIndex, 1);
    res.json({ message: 'Account deleted successfully' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));