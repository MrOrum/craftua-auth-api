// server.js — CraftUA Auth API

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

// ----------------------
// DATABASE CONNECTION
// ----------------------
const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ----------------------
// MIDDLEWARE
// ----------------------
app.use(cors());
app.use(express.json());

// ----------------------
// HELPERS
// ----------------------
function generateToken() {
    return crypto.randomBytes(32).toString("hex");
}

async function isUserBanned(userId) {
    const res = await db.query(
        `SELECT 1 FROM bans 
         WHERE user_id = $1 
         AND (expires_at IS NULL OR expires_at > NOW())
         LIMIT 1`,
        [userId]
    );
    return res.rowCount > 0;
}

async function getUserRoles(userId) {
    const res = await db.query(
        `SELECT role FROM roles WHERE user_id = $1`,
        [userId]
    );
    return res.rows.map(r => r.role);
}

// ----------------------
// AUTH ROUTER (/auth/...)
// ----------------------
const auth = express.Router();

// REGISTER
auth.post("/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password)
            return res.status(400).json({ success: false, message: "Заповніть всі поля" });

        const exists = await db.query(
            `SELECT id FROM users WHERE username = $1 OR email = $2`,
            [username, email]
        );

        if (exists.rowCount > 0)
            return res.status(409).json({ success: false, message: "Користувач вже існує" });

        const hash = await bcrypt.hash(password, 10);

        const user = await db.query(
            `INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)
             RETURNING id, username, email, created_at`,
            [username, email, hash]
        );

        res.json({ success: true, user: user.rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// LOGIN (ВИПРАВЛЕНИЙ)
auth.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        const userRes = await db.query(
            `SELECT * FROM users WHERE username = $1 OR email = $1`,
            [username]
        );

        if (userRes.rowCount === 0)
            return res.status(401).json({ success: false, message: "Невірний логін або пароль" });

        const user = userRes.rows[0];

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match)
            return res.status(401).json({ success: false, message: "Невірний логін або пароль" });

        if (await isUserBanned(user.id))
            return res.status(403).json({ success: false, message: "Користувач заблокований" });

        const token = generateToken();
        const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

        await db.query(
            `INSERT INTO tokens (user_id, token, expires_at)
             VALUES ($1, $2, $3)`,
            [user.id, token, expires]
        );

        const roles = await getUserRoles(user.id);

        res.json({
            success: true,
            token,
            expires_at: expires,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                roles
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// VERIFY TOKEN (ВИПРАВЛЕНИЙ)
auth.post("/verify", async (req, res) => {
    try {
        const { token } = req.body;

        if (!token)
            return res.status(400).json({ success: false, valid: false, message: "Немає токена" });

        const result = await db.query(
            `SELECT t.*, u.username, u.email, u.id AS user_id
             FROM tokens t
             JOIN users u ON u.id = t.user_id
             WHERE t.token = $1`,
            [token]
        );

        if (result.rowCount === 0)
            return res.status(401).json({ success: false, valid: false, message: "Невірний токен" });

        const row = result.rows[0];

        if (new Date(row.expires_at) < new Date())
            return res.status(401).json({ success: false, valid: false, message: "Токен прострочений" });

        if (await isUserBanned(row.user_id))
            return res.status(403).json({ success: false, valid: false, message: "Користувач заблокований" });

        const roles = await getUserRoles(row.user_id);

        res.json({
            success: true,
            valid: true,
            user: {
                id: row.user_id,
                username: row.username,
                email: row.email,
                roles
            }
        });

    } catch (err) {
        res.status(500).json({ success: false, valid: false, message: err.message });
    }
});

// LOGOUT
auth.post("/logout", async (req, res) => {
    try {
        const { token } = req.body;

        if (!token)
            return res.status(400).json({ success: false, message: "Немає токена" });

        await db.query(`DELETE FROM tokens WHERE token = $1`, [token]);

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Підключаємо /auth/*
app.use("/auth", auth);

// ROOT
app.get("/", (req, res) => {
    res.json({ ok: true, service: "CraftUA Auth API" });
});

// START SERVER
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
