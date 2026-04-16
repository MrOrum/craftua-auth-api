import express from "express";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcrypt";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// ---------------- PostgreSQL ----------------

const pool = new Pool({
    connectionString: "postgresql://craftua_auth_db_user:zRlPgq01j4SeTZIflB8BWQ2qPCmVECl3@dpg-d7ggpo0sfn5c738o7f6g-a.frankfurt-postgres.render.com/craftua_auth_db",
    ssl: { rejectUnauthorized: false }
});

// Створення таблиці, якщо її немає
async function initDB() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            token TEXT NOT NULL
        );
    `);
}

initDB();

// ---------------- ROUTES ----------------

app.get("/", (req, res) => {
    res.send("Auth API is running with PostgreSQL");
});

// ---------------- REGISTER ----------------

app.post("/auth/register", async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.json({ success: false, message: "Заповніть всі поля" });
    }

    try {
        const existing = await pool.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );

        if (existing.rows.length > 0) {
            return res.json({ success: false, message: "Користувач вже існує" });
        }

        const hashed = await bcrypt.hash(password, 10);
        const token = uuidv4();

        await pool.query(
            "INSERT INTO users (username, email, password, token) VALUES ($1, $2, $3, $4)",
            [username, email, hashed, token]
        );

        return res.json({
            success: true,
            message: "Акаунт створено",
            token
        });

    } catch (err) {
        console.error(err);
        return res.json({ success: false, message: "Помилка сервера" });
    }
});

// ---------------- LOGIN ----------------

app.post("/auth/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );

        if (result.rows.length === 0) {
            return res.json({ success: false, message: "Користувача не знайдено" });
        }

        const user = result.rows[0];

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.json({ success: false, message: "Невірний пароль" });
        }

        return res.json({
            success: true,
            message: "Вхід успішний",
            token: user.token
        });

    } catch (err) {
        console.error(err);
        return res.json({ success: false, message: "Помилка сервера" });
    }
});

// ---------------- VERIFY TOKEN ----------------

app.post("/auth/verify", async (req, res) => {
    const { token } = req.body;

    if (!token) return res.json({ valid: false });

    try {
        const result = await pool.query(
            "SELECT * FROM users WHERE token = $1",
            [token]
        );

        return res.json({ valid: result.rows.length > 0 });

    } catch (err) {
        console.error(err);
        return res.json({ valid: false });
    }
});

// ---------------- START SERVER ----------------

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log("Auth API running on port " + PORT);
});
