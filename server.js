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
app.use(express.urlencoded({ extended: true })); // ensure urlencoded parsing too

// --- CONFIG ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "superSecretKeyChangeMe";
const ADMIN_KEY = process.env.ADMIN_KEY || "Sahara89."; // set on Render for security
const MAX_DEVICES = 4;

// --- POSTGRES SETUP ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// --- AUTH ---
app.post("/api/login", async (req, res) => {
  console.log("📥 Raw login body:", req.body); // DEBUG LOG
  const { username, password, deviceId } = req.body;
  if (!username || !password || !deviceId) {
    return res.json({ success: false, message: "Missing credentials or deviceId" });
  }
  return res.json({ success: true, debug: true }); // simplified for debug
});

// --- HEALTH ---
app.get("/api/health", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// --- START ---
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
