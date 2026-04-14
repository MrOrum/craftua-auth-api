import express from "express";
import fs from "fs";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const USERS_FILE = "./users.json";

if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, "[]");
}

function loadUsers() {
    return JSON.parse(fs.readFileSync(USERS_FILE));
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

app.get("/", (req, res) => {
    res.send("Auth API is running");
});

app.post("/auth/register", (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.json({ success: false, message: "Заповніть всі поля" });
    }

    const users = loadUsers();

    if (users.find(u => u.username === username)) {
        return res.json({ success: false, message: "Користувач вже існує" });
    }

    const newUser = {
        username,
        password,
        email,
        token: uuidv4()
    };

    users.push(newUser);
    saveUsers(users);

    return res.json({
        success: true,
        message: "Акаунт створено",
        token: newUser.token
    });
});

app.post("/auth/login", (req, res) => {
    const { username, password } = req.body;

    const users = loadUsers();
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.json({ success: false, message: "Користувача не знайдено" });
    }

    if (user.password !== password) {
        return res.json({ success: false, message: "Невірний пароль" });
    }

    return res.json({
        success: true,
        message: "Вхід успішний",
        token: user.token
    });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log("Auth API running on port " + PORT);
});
