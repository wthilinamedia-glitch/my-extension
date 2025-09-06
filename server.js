
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const { DateTime } = require("luxon");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

// --- CONFIG ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "superSecretKeyChangeMe";
const ADMIN_KEY = process.env.ADMIN_KEY || "change-this-admin-key"; // used to protect admin endpoints

// --- DATABASE SETUP ---
const db = new sqlite3.Database("./users.db");

// Create table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  subscription_active INTEGER DEFAULT 1,
  subscription_until TEXT
)`);

// Ensure subscription_until column exists (migration-safe)
db.run(`ALTER TABLE users ADD COLUMN subscription_until TEXT`, (err) => {
  // ignore error if column already exists
});

// --- TIME HELPERS ---
function nextThursdayCutoffISO() {
  const now = DateTime.now().setZone("Asia/Colombo");
  let cutoff = now.set({ weekday: 4, hour: 23, minute: 59, second: 0, millisecond: 0 });
  if (cutoff <= now) cutoff = cutoff.plus({ weeks: 1 });
  return cutoff.toUTC().toISO(); // ISO string in UTC
}

function nextThursdayExpSeconds() {
  return Math.floor(DateTime.fromISO(nextThursdayCutoffISO()).toSeconds());
}

// --- TOKEN ---
function makeToken(username) {
  const exp = nextThursdayExpSeconds();
  return jwt.sign({ sub: username, exp }, JWT_SECRET);
}

// --- ADMIN GUARD ---
function requireAdminKey(req, res, next) {
  const key = req.headers["x-admin-key"] || req.body.adminKey;
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ success: false, message: "Unauthorized (admin key required)" });
  }
  next();
}

// --- AUTH ---
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ success: false, message: "Missing credentials" });

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) return res.json({ success: false, message: "DB error" });
    if (!user) return res.json({ success: false, message: "User not found" });

    const ok = bcrypt.compareSync(password, user.password);
    if (!ok) return res.json({ success: false, message: "Wrong password" });

    if (!user.subscription_active) {
      return res.json({ success: false, message: "Subscription inactive" });
    }

    // Weekly subscription rule: must be before subscription_until
    if (user.subscription_until) {
      const now = DateTime.now().toUTC();
      const until = DateTime.fromISO(user.subscription_until, { zone: "utc" });
      if (now > until) {
        return res.json({ success: false, message: "Subscription expired. Please renew." });
      }
    } else {
      // If missing, treat as expired and require renewal
      return res.json({ success: false, message: "Subscription expired. Please renew." });
    }

    const token = makeToken(user.username);
    res.json({ success: true, token });
  });
});

app.post("/api/verify", (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.json({ valid: false, reason: "missing_token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return res.json({ valid: true, user: decoded.sub, exp: decoded.exp });
  } catch (e) {
    return res.json({ valid: false, reason: "expired_or_invalid" });
  }
});

// --- ADMIN: REGISTER (creates user, sets subscription until next Thursday 23:59 SLT) ---
app.post("/api/admin/register", requireAdminKey, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ success: false, message: "Missing username or password" });
  }
  const hashed = bcrypt.hashSync(password, 10);
  const untilISO = nextThursdayCutoffISO();

  db.run(
    "INSERT INTO users (username, password, subscription_active, subscription_until) VALUES (?, ?, ?, ?)",
    [username, hashed, 1, untilISO],
    (err) => {
      if (err) return res.json({ success: false, message: "User already exists" });
      res.json({ success: true, message: "User registered", subscription_until: untilISO });
    }
  );
});

// --- ADMIN: RENEW (extends existing user to next Thursday 23:59 SLT) ---
app.post("/api/admin/renew", requireAdminKey, (req, res) => {
  const { username } = req.body;
  if (!username) return res.json({ success: false, message: "Missing username" });

  const untilISO = nextThursdayCutoffISO();
  db.run(
    "UPDATE users SET subscription_active = 1, subscription_until = ? WHERE username = ?",
    [untilISO, username],
    function (err) {
      if (err) return res.json({ success: false, message: "DB error" });
      if (this.changes === 0) return res.json({ success: false, message: "User not found" });
      res.json({ success: true, message: "Subscription renewed", subscription_until: untilISO });
    }
  );
});

// --- (Optional) ADMIN: CHECK USER ---
app.post("/api/admin/check", requireAdminKey, (req, res) => {
  const { username } = req.body;
  if (!username) return res.json({ success: false, message: "Missing username" });
  db.get("SELECT username, subscription_active, subscription_until FROM users WHERE username = ?", [username], (err, user) => {
    if (err) return res.json({ success: false, message: "DB error" });
    if (!user) return res.json({ success: false, message: "User not found" });
    res.json({ success: true, user });
  });
});

// --- HEALTH ---
app.get("/api/health", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// --- ADMIN PANEL STATIC PAGE ---
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// --- START ---
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
