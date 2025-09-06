const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const { DateTime } = require("luxon");

const app = express();
const path = require("path");

// Serve admin.html at /admin
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.use(cors());
app.use(express.json());

// --- CONFIG ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "superSecretKey"; // ✅ override this in Render

// --- DATABASE SETUP ---
const db = new sqlite3.Database("./users.db");

// Create users table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  subscription_active INTEGER
)`);

// --- HELPER: Next Thursday 11:59 PM Sri Lanka time ---
function nextThursdayExp() {
  const zone = "Asia/Colombo"; // Sri Lanka timezone
  const now = DateTime.now().setZone(zone);

  // Luxon: Monday=1 ... Sunday=7 ; Thursday=4
  let cutoff = now.set({
    weekday: 4,
    hour: 23,
    minute: 59,
    second: 0,
    millisecond: 0,
  });

  // If cutoff already passed this week → move to next week
  if (cutoff <= now) {
    cutoff = cutoff.plus({ weeks: 1 });
  }

  // Return UNIX seconds (UTC)
  return Math.floor(cutoff.toUTC().toSeconds());
}

// --- HELPER: Issue Token ---
function makeToken(username) {
  const exp = nextThursdayExp();
  return jwt.sign({ sub: username, exp }, JWT_SECRET);
}

// --- REGISTER USER ---
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ success: false, message: "Missing username or password" });
  }

  const hashed = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users (username, password, subscription_active) VALUES (?, ?, ?)",
    [username, hashed, 1],
    (err) => {
      if (err) {
        return res.json({ success: false, message: "User already exists" });
      }
      res.json({ success: true, message: "User registered" });
    }
  );
});

// --- LOGIN USER ---
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) return res.json({ success: false, message: "DB error" });
    if (!user) return res.json({ success: false, message: "User not found" });

    const validPass = bcrypt.compareSync(password, user.password);
    if (!validPass) return res.json({ success: false, message: "Wrong password" });

    if (!user.subscription_active) {
      return res.json({ success: false, message: "Subscription inactive" });
    }

    const token = makeToken(user.username);
    res.json({ success: true, token });
  });
});

// --- VERIFY TOKEN ---
app.post("/api/verify", (req, res) => {
  const { token } = req.body;
  if (!token) return res.json({ valid: false, reason: "missing_token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, user: decoded.sub, exp: decoded.exp });
  } catch {
    res.json({ valid: false, reason: "expired_or_invalid" });
  }
});

// --- HEALTH CHECK ---
app.get("/api/health", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// --- START SERVER ---
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
