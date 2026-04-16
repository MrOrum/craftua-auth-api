// server.js
// CraftUA Auth API

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

// ---------- DB POOL ----------
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---------- MIDDLEWARE ----------
app.use(cors());
app.use(express.json());

// ---------- HELPERS ----------
async function isUserBanned(userId) {
  const res = await db.query(
    `
    SELECT 1
    FROM bans
    WHERE user_id = $1
      AND (expires_at IS NULL OR expires_at > NOW())
    LIMIT 1
  `,
    [userId]
  );
  return res.rowCount > 0;
}

async function getUserRoles(userId) {
  const res = await db.query(
    `
    SELECT role
    FROM roles
    WHERE user_id = $1
  `,
    [userId]
  );
  return res.rows.map(r => r.role);
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

// ---------- ROUTES ----------

// Health / DB test
app.get("/db-test", async (req, res) => {
  try {
    const result = await db.query("SELECT NOW()");
    res.json({ ok: true, time: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Register
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ ok: false, error: "Missing fields" });
    }

    const existing = await db.query(
      "SELECT id FROM users WHERE username = $1 OR email = $2",
      [username, email]
    );
    if (existing.rowCount > 0) {
      return res
        .status(409)
        .json({ ok: false, error: "User with this username or email exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const userRes = await db.query(
      `
      INSERT INTO users (username, email, password_hash)
      VALUES ($1, $2, $3)
      RETURNING id, username, email, role, created_at
    `,
      [username, email, passwordHash]
    );

    const user = userRes.rows[0];

    res.json({ ok: true, user });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Login (site / launcher)
app.post("/login", async (req, res) => {
  try {
    const { login, password } = req.body; // login = username or email

    if (!login || !password) {
      return res.status(400).json({ ok: false, error: "Missing fields" });
    }

    const userRes = await db.query(
      `
      SELECT *
      FROM users
      WHERE username = $1 OR email = $1
    `,
      [login]
    );

    if (userRes.rowCount === 0) {
      return res.status(401).json({ ok: false, error: "Invalid credentials" });
    }

    const user = userRes.rows[0];

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      await db.query(
        `
        INSERT INTO auth_logs (user_id, ip, user_agent, success)
        VALUES ($1, $2, $3, false)
      `,
        [user.id, req.ip, req.headers["user-agent"] || ""]
      );
      return res.status(401).json({ ok: false, error: "Invalid credentials" });
    }

    if (await isUserBanned(user.id)) {
      return res.status(403).json({ ok: false, error: "User is banned" });
    }

    const token = generateToken();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 днів

    await db.query(
      `
      INSERT INTO tokens (user_id, token, expires_at)
      VALUES ($1, $2, $3)
    `,
      [user.id, token, expiresAt]
    );

    await db.query(
      `
      UPDATE users
      SET last_login = NOW()
      WHERE id = $1
    `,
      [user.id]
    );

    await db.query(
      `
      INSERT INTO auth_logs (user_id, ip, user_agent, success)
      VALUES ($1, $2, $3, true)
    `,
      [user.id, req.ip, req.headers["user-agent"] || ""]
    );

    const roles = await getUserRoles(user.id);

    res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        roles
      },
      expires_at: expiresAt
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Alias for launcher auth (можеш використовувати /auth у лаунчері)
app.post("/auth", async (req, res) => {
  // просто прокидуємо на /login
  req.url = "/login";
  app._router.handle(req, res);
});

// Validate token
app.get("/validate-token", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return res.status(401).json({ ok: false, error: "No token" });
    }

    const tokenRes = await db.query(
      `
      SELECT t.*, u.username, u.email, u.role AS main_role, u.id AS user_id
      FROM tokens t
      JOIN users u ON u.id = t.user_id
      WHERE t.token = $1
    `,
      [token]
    );

    if (tokenRes.rowCount === 0) {
      return res.status(401).json({ ok: false, error: "Invalid token" });
    }

    const row = tokenRes.rows[0];

    if (row.expires_at && new Date(row.expires_at) < new Date()) {
      return res.status(401).json({ ok: false, error: "Token expired" });
    }

    if (await isUserBanned(row.user_id)) {
      return res.status(403).json({ ok: false, error: "User is banned" });
    }

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

// Logout (invalidate token)
app.post("/logout", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return res.status(400).json({ ok: false, error: "No token" });
    }

    await db.query("DELETE FROM tokens WHERE token = $1", [token]);

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Latest launcher update
app.get("/launcher/latest", async (req, res) => {
  try {
    const result = await db.query(
      `
      SELECT *
      FROM launcher_updates
      ORDER BY created_at DESC
      LIMIT 1
    `
    );
    if (result.rowCount === 0) {
      return res.json({ ok: true, update: null });
    }
    res.json({ ok: true, update: result.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Latest game update
app.get("/game/latest", async (req, res) => {
  try {
    const result = await db.query(
      `
      SELECT *
      FROM game_updates
      ORDER BY created_at DESC
      LIMIT 1
    `
    );
    if (result.rowCount === 0) {
      return res.json({ ok: true, update: null });
    }
    res.json({ ok: true, update: result.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Root
app.get("/", (req, res) => {
  res.json({ ok: true, service: "CraftUA Auth API" });
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
