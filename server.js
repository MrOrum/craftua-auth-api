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
// ROUTES
// ----------------------

// DB TEST
app.get("/db-test", async (req, res) => {
    try {
        const result = await db.query("SELECT NOW()");
        res.json({ ok: true, time: result.rows[0].now });
    } catch (err) {
        res.json({ ok: false, error: err.message });
    }
});

// REGISTER
app.post("/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password)
            return res.status(400).json({ ok: false, error: "Missing fields" });

        const exists = await db.query(
            `SELECT id FROM users WHERE username = $1 OR email = $2`,
            [username, email]
        );

        if (exists.rowCount > 0)
            return res.status(409).json({ ok: false, error: "User exists" });

        const hash = await bcrypt.hash(password, 10);

        const user = await db.query(
            `INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)
             RETURNING id, username, email, role, created_at`,
            [username, email, hash]
        );

        res.json({ ok: true, user: user.rows[0] });
    } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
    }
});

// LOGIN
app.post("/login", async (req, res) => {
    try {
        const { login, password } = req.body;

        const userRes = await db.query(
            `SELECT * FROM users WHERE username = $1 OR email = $1`,
            [login]
        );

        if (userRes.rowCount === 0)
            return res.status(401).json({ ok: false, error: "Invalid credentials" });

        const user = userRes.rows[0];

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match)
            return res.status(401).json({ ok: false, error: "Invalid credentials" });

        if (await isUserBanned(user.id))
            return res.status(403).json({ ok: false, error: "User banned" });

        const token = generateToken();
        const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

        await db.query(
            `INSERT INTO tokens (user_id, token, expires_at)
             VALUES ($1, $2, $3)`,
            [user.id, token, expires]
        );

        await db.query(
            `UPDATE users SET last_login = NOW() WHERE id = $1`,
            [user.id]
        );

        const roles = await getUserRoles(user.id);

        res.json({
            ok: true,
            token,
            expires_at: expires,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                roles
            }
        });
    } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
    }
});

// AUTH (alias for launcher)
app.post("/auth", (req, res) => {
    req.url = "/login";
    app._router.handle(req, res);
});

// VALIDATE TOKEN
app.get("/validate-token", async (req, res) => {
    try {
        const auth = req.headers.authorization || "";
        const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

        if (!token)
            return res.status(401).json({ ok: false, error: "No token" });

        const result = await db.query(
            `SELECT t.*, u.username, u.email, u.role AS main_role, u.id AS user_id
             FROM tokens t
             JOIN users u ON u.id = t.user_id
             WHERE t.token = $1`,
            [token]
        );

        if (result.rowCount === 0)
            return res.status(401).json({ ok: false, error: "Invalid token" });

        const row = result.rows[0];

        if (new Date(row.expires_at) < new Date())
            return res.status(401).json({ ok: false, error: "Token expired" });

        if (await isUserBanned(row.user_id))
            return res.status(403).json({ ok: false, error: "User banned" });

        const roles = await getUserRoles(row.user_id);

        res.json({
            ok: true,
            user: {
                id: row.user_id,
                username: row.username,
                email: row.email,
                role: row.main_role,
                roles
            }
        });
    } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
    }
});

// LOGOUT
app.post("/logout", async (req, res) => {
    try {
        const auth = req.headers.authorization || "";
        const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

        if (!token)
            return res.status(400).json({ ok: false, error: "No token" });

        await db.query(`DELETE FROM tokens WHERE token = $1`, [token]);

        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
    }
});

// LAUNCHER UPDATE
app.get("/launcher/latest", async (req, res) => {
    try {
        const result = await db.query(
            `SELECT * FROM launcher_updates ORDER BY created_at DESC LIMIT 1`
        );
        res.json({ ok: true, update: result.rows[0] || null });
    } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
    }
});

// GAME UPDATE
app.get("/game/latest", async (req, res) => {
    try {
        const result = await db.query(
            `SELECT * FROM game_updates ORDER BY created_at DESC LIMIT 1`
        );
        res.json({ ok: true, update: result.rows[0] || null });
    } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
    }
});

// ROOT
app.get("/", (req, res) => {
    res.json({ ok: true, service: "CraftUA Auth API" });
});

// START SERVER
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
