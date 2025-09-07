
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { DateTime } = require("luxon");
const path = require("path");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

// --- CONFIG ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "superSecretKey12345.";
const ADMIN_KEY = process.env.ADMIN_KEY || "Sahara89."; // <-- fallback; set ADMIN_KEY in Render env
const MAX_DEVICES = parseInt(process.env.MAX_DEVICES || "4", 10);

// --- POSTGRES SETUP ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Initialize tables
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT NOT NULL,
      subscription_active BOOLEAN DEFAULT true,
      subscription_until TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_devices (
      id SERIAL PRIMARY KEY,
      username TEXT,
      device_id TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  console.log("✅ Users and user_devices tables ready");
})().catch(err => {
  console.error("DB init error:", err);
  process.exit(1);
});

// --- TIME HELPERS ---
function nextThursdayCutoffISO() {
  const now = DateTime.now().setZone("Asia/Colombo");
  let cutoff = now.set({ weekday: 4, hour: 23, minute: 59, second: 0, millisecond: 0 });
  if (cutoff <= now) cutoff = cutoff.plus({ weeks: 1 });
  return cutoff.toUTC().toISO();
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
app.post("/api/login", async (req, res) => {
  const { username, password, deviceId } = req.body;
  if (!username || !password || !deviceId) {
    return res.json({ success: false, message: "Missing credentials or deviceId" });
  }

  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = rows[0];
    if (!user) return res.json({ success: false, message: "User not found" });

    const ok = bcrypt.compareSync(password, user.password);
    if (!ok) return res.json({ success: false, message: "Wrong password" });

    if (!user.subscription_active) {
      return res.json({ success: false, message: "Subscription inactive" });
    }

    if (user.subscription_until) {
      const now = DateTime.now().toUTC();
      const until = DateTime.fromJSDate(user.subscription_until);
      if (now > until) {
        return res.json({ success: false, message: "Subscription expired. Please renew." });
      }
    } else {
      return res.json({ success: false, message: "Subscription expired. Please renew." });
    }

    // --- Device check & register if new ---
    const { rows: deviceRows } = await pool.query(
      "SELECT device_id FROM user_devices WHERE username = $1",
      [username]
    );
    const knownDevices = deviceRows.map(r => r.device_id);

    if (!knownDevices.includes(deviceId)) {
      if (knownDevices.length >= MAX_DEVICES) {
        return res.json({ success: false, message: `Too many devices registered. Limit is ${MAX_DEVICES}.` });
      }
      await pool.query(
        "INSERT INTO user_devices (username, device_id) VALUES ($1, $2)",
        [username, deviceId]
      );
    }

    const token = makeToken(user.username);
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "DB error" });
  }
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

// --- ADMIN: REGISTER (sets subscription until next Thu 23:59 SLT) ---
app.post("/api/admin/register", requireAdminKey, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ success: false, message: "Missing username or password" });
  }
  const hashed = bcrypt.hashSync(password, 10);
  const untilISO = nextThursdayCutoffISO();

  try {
    await pool.query(
      "INSERT INTO users (username, password, subscription_active, subscription_until) VALUES ($1, $2, $3, $4)",
      [username, hashed, true, untilISO]
    );
    res.json({ success: true, message: "User registered", subscription_until: untilISO });
  } catch (err) {
    if (err.code === "23505") {
      res.json({ success: false, message: "User already exists" });
    } else {
      console.error(err);
      res.json({ success: false, message: "DB error" });
    }
  }
});

// --- ADMIN: RENEW ---
app.post("/api/admin/renew", requireAdminKey, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.json({ success: false, message: "Missing username" });

  const untilISO = nextThursdayCutoffISO();
  try {
    const result = await pool.query(
      "UPDATE users SET subscription_active = true, subscription_until = $1 WHERE username = $2",
      [untilISO, username]
    );
    if (result.rowCount === 0) {
      return res.json({ success: false, message: "User not found" });
    }
    res.json({ success: true, message: "Subscription renewed", subscription_until: untilISO });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "DB error" });
  }
});

// --- ADMIN: CHECK ---
app.post("/api/admin/check", requireAdminKey, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.json({ success: false, message: "Missing username" });
  try {
    const { rows } = await pool.query(
      "SELECT username, subscription_active, subscription_until FROM users WHERE username = $1",
      [username]
    );
    if (rows.length === 0) return res.json({ success: false, message: "User not found" });
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "DB error" });
  }
});

// --- ADMIN: LIST DEVICES ---
app.post("/api/admin/devices", requireAdminKey, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.json({ success: false, message: "Missing username" });

  try {
    const { rows } = await pool.query(
      "SELECT id, device_id, created_at FROM user_devices WHERE username = $1 ORDER BY created_at ASC",
      [username]
    );
    res.json({ success: true, devices: rows });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "DB error" });
  }
});

// --- ADMIN: RESET DEVICES ---
app.post("/api/admin/reset-devices", requireAdminKey, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.json({ success: false, message: "Missing username" });

  try {
    const result = await pool.query(
      "DELETE FROM user_devices WHERE username = $1",
      [username]
    );
    res.json({ success: true, message: `Removed ${result.rowCount} devices for ${username}` });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "DB error" });
  }
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
