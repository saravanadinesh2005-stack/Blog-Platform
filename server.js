const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database('./blog.db');
const SECRET_KEY = 'super_secret_key_change_in_production';

// Initialize Database Tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT, user_id INTEGER
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT, post_id INTEGER, user_id INTEGER
    )`);
});

// Middleware for Authentication
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = decoded;
        next();
    });
};

// 1. User Registration & Login
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
        if (err) return res.status(400).json({ error: "Username exists" });
        res.json({ message: "User registered successfully" });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }
        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY);
        res.json({ token, username: user.username });
    });
});

// 2. Blog Posts CRUD
app.get('/api/posts', (req, res) => {
    db.all(`SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id`, [], (err, rows) => {
        res.json(rows);
    });
});

app.post('/api/posts', authenticate, (req, res) => {
    const { title, content } = req.body;
    db.run(`INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)`, [title, content, req.user.id], function(err) {
        res.json({ id: this.lastID, title, content, username: req.user.username });
    });
});

app.delete('/api/posts/:id', authenticate, (req, res) => {
    db.run(`DELETE FROM posts WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], function(err) {
        if (this.changes === 0) return res.status(403).json({ error: "Unauthorized to delete this post" });
        res.json({ message: "Post deleted" });
    });
});

// 3. Comments
app.get('/api/posts/:id/comments', (req, res) => {
    db.all(`SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE post_id = ?`, [req.params.id], (err, rows) => {
        res.json(rows);
    });
});

app.post('/api/posts/:id/comments', authenticate, (req, res) => {
    const { text } = req.body;
    db.run(`INSERT INTO comments (text, post_id, user_id) VALUES (?, ?, ?)`, [text, req.params.id, req.user.id], function(err) {
        res.json({ id: this.lastID, text, username: req.user.username });
    });
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));