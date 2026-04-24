// CraftUA Auth API — GML Compatible Final Version

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

// ----------------------
// DATABASE
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

// ----------------------
// AUTH ROUTER
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

        await db.query(
            `INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)`,
            [username, email, hash]
        );

        res.json({ success: true, message: "Реєстрація успішна" });

    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// LOGIN — GML COMPATIBLE
auth.post("/login", async (req, res) => {
    try {
        const login = req.body.username || req.body.Login;
        const password = req.body.password || req.body.Password;

        if (!login || !password)
            return res.json({ success: false, message: "Заповніть логін і пароль" });

        const userRes = await db.query(
            `SELECT * FROM users WHERE username = $1 OR email = $1`,
            [login]
        );

        if (userRes.rowCount === 0)
            return res.json({ success: false, message: "Невірний логін або пароль" });

        const user = userRes.rows[0];

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match)
            return res.json({ success: false, message: "Невірний логін або пароль" });

        const token = generateToken();

        await db.query(
            `INSERT INTO tokens (user_id, token, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '30 days')`,
            [user.id, token]
        );

        // ВАЖЛИВО: формат під GML Launcher
        return res.json({
            success: true,
            uuid: user.uuid,
            username: user.username,
            token: token
        });

    } catch (err) {
        return res.json({ success: false, message: "Помилка сервера: " + err.message });
    }
});

// VERIFY
auth.post("/verify", async (req, res) => {
    try {
        const { token } = req.body;

        if (!token)
            return res.json({ success: false, valid: false });

        const result = await db.query(
            `SELECT users.id, users.username, users.email, users.uuid
             FROM tokens
             JOIN users ON users.id = tokens.user_id
             WHERE tokens.token = $1
             AND tokens.expires_at > NOW()`,
            [token]
        );

        if (result.rowCount === 0)
            return res.json({ success: false, valid: false });

        res.json({
            success: true,
            valid: true,
            user: result.rows[0]
        });

    } catch (err) {
        res.json({ success: false, valid: false, message: err.message });
    }
});

// LOGOUT
auth.post("/logout", async (req, res) => {
    try {
        const { token } = req.body;

        await db.query(
            `DELETE FROM tokens WHERE token = $1`,
            [token]
        );

        res.json({ success: true });

    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});

// ROUTER
app.use("/auth", auth);

// ROOT
app.get("/", (req, res) => {
    res.json({ ok: true, service: "CraftUA Auth API (GML Compatible)" });
});

// START
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
