// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(cors());

// ------------------------------
// 0) LOGGING HELPERS
// ------------------------------
const LOG_LEVEL = process.env.LOG_LEVEL || 'debug'; // debug | info | warn | error
const levelRank = { debug: 10, info: 20, warn: 30, error: 40 };

function log(level, reqId, msg, obj) {
  if (levelRank[level] < levelRank[LOG_LEVEL]) return;
  const base = `[${new Date().toISOString()}] [${level.toUpperCase()}] [rid:${reqId}] ${msg}`;
  if (obj !== undefined) console.log(base, obj);
  else console.log(base);
}

function maskToken(token) {
  if (!token || token.length < 16) return '***';
  return token.slice(0, 8) + '...' + token.slice(-6);
}

function safeHeaders(headers) {
  // avoid leaking secrets
  const h = { ...headers };
  if (h.authorization) h.authorization = maskToken(h.authorization);
  if (h.cookie) h.cookie = '***';
  return h;
}

function getReqId(req) {
  return req.headers['x-request-id'] || crypto.randomUUID();
}

// Request logger + duration
app.use((req, res, next) => {
  req.reqId = getReqId(req);
  req._startAt = Date.now();

  log('info', req.reqId, `➡️ ${req.method} ${req.originalUrl}`, {
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    ua: req.headers['user-agent'],
    headers: safeHeaders(req.headers),
  });

  res.on('finish', () => {
    const ms = Date.now() - req._startAt;
    log('info', req.reqId, `⬅️ ${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`);
  });

  next();
});

// ------------------------------
// 1) MONGODB CONFIGURATION
// ------------------------------
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URI) throw new Error("❌ MONGO_URI missing");
if (!JWT_SECRET) throw new Error("❌ JWT_SECRET missing");

let cached = global.mongoose;
if (!cached) cached = global.mongoose = { conn: null, promise: null };

async function connectDB(reqId) {
  if (cached.conn) {
    log('debug', reqId, '🟢 DB already connected (cached.conn)');
    return cached.conn;
  }

  if (!cached.promise) {
    log('info', reqId, '🟡 DB connecting...', {
      mongoUriHint: MONGO_URI.replace(/\/\/.*@/, '//***@') // hide creds
    });

    cached.promise = mongoose
      .connect(MONGO_URI, {
        bufferCommands: false,
        serverSelectionTimeoutMS: 8000,
      })
      .then((m) => {
        log('info', reqId, '🟢 DB connected');
        return m;
      })
      .catch((err) => {
        log('error', reqId, '🔴 DB connect failed', {
          name: err.name,
          message: err.message,
          code: err.code,
        });
        throw err;
      });
  }

  cached.conn = await cached.promise;
  return cached.conn;
}

// ------------------------------
// 2) SCHEMAS
// ------------------------------

// IMPORTANT: add fields you actually use in settings toggles
const UserProfileSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true }, // email or auth ID
    bio: { type: String, default: "" },
    organization: { type: String, default: "" },
    role: { type: String, default: "" },
    phone: { type: String, default: "" },
    timezone: { type: String, default: "Africa/Tunis" },
    preferences: {
      notifications: {
        // 👇 add missing toggles so they persist
        push: { type: Boolean, default: true },
        fall_detection: { type: Boolean, default: true },

        emailAlerts: { type: Boolean, default: true },
        criticalOnly: { type: Boolean, default: false },
        dailySummary: { type: Boolean, default: true },
        maintenanceReminders: { type: Boolean, default: true }
      },
      units: {
        temperature: { type: String, enum: ['celsius', 'fahrenheit'], default: 'celsius' },
        distance: { type: String, enum: ['metric', 'imperial'], default: 'metric' }
      },
      language: { type: String, default: "en" }
    }
  },
  {
    timestamps: true,
    collection: 'userProfiles'
  }
);

UserProfileSchema.index({ userId: 1 }, { unique: true });

const UserSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true },
    name: { type: String, default: "" },
    avatar: { type: String, default: "" },
    image: { type: String, default: "" },
    organization: { type: String, default: "" },
    phone: { type: String, default: "" },
    role: { type: String, default: "user" },
    isProfileComplete: { type: Boolean, default: false },
    lastLogin: { type: Date }
  },
  { timestamps: true, collection: "users" }
);

const User = mongoose.models.User || mongoose.model("User", UserSchema);
const UserProfile = mongoose.models.UserProfile || mongoose.model('UserProfile', UserProfileSchema);

// ------------------------------
// 3) AUTH MIDDLEWARE (DETAILED)
// ------------------------------
const authenticateToken = (req, res, next) => {
  const reqId = req.reqId;

  const auth = req.headers['authorization'];
  const token = auth?.startsWith('Bearer ') ? auth.split(' ')[1] : null;

  if (!token) {
    log('warn', reqId, '🔒 Token missing');
    return res.status(401).json({ message: 'Token missing' });
  }

  log('debug', reqId, '🔐 Token received', { token: maskToken(token) });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      log('warn', reqId, '⛔ Token invalid', { name: err.name, message: err.message });
      return res.status(403).json({ message: 'Token invalid' });
    }

    // Log decoded payload (safe)
    log('debug', reqId, '✅ Token decoded', {
      keys: Object.keys(decoded || {}),
      decoded,
    });

    // identify
    req.userIdentifier = decoded.email || decoded.id || decoded.userId || decoded.sub;

    if (!req.userIdentifier) {
      log('error', reqId, '❌ Invalid token payload: missing identifier', { decoded });
      return res.status(400).json({ message: 'Invalid token payload' });
    }

    log('info', reqId, '👤 userIdentifier resolved', { userIdentifier: req.userIdentifier });

    next();
  });
};

// ------------------------------
// 4) ROUTES
// ------------------------------

// Health
app.get('/api/ping', (req, res) => {
  res.json({
    ok: true,
    originalUrl: req.originalUrl,
    path: req.path,
    method: req.method,
    hasAuthHeader: !!req.headers.authorization,
  });
});

// Debug token
app.get('/api/debug-token', authenticateToken, (req, res) => {
  res.json({
    ok: true,
    userIdentifier: req.userIdentifier,
  });
});

// Debug DB + collections counts (requires auth)
app.get('/api/debug-db', authenticateToken, async (req, res) => {
  const reqId = req.reqId;
  try {
    await connectDB(reqId);

    const dbName = mongoose.connection?.name;
    const readyState = mongoose.connection?.readyState;

    const usersCount = await User.countDocuments({});
    const profilesCount = await UserProfile.countDocuments({});

    log('info', reqId, '🧾 DB Debug', { dbName, readyState, usersCount, profilesCount });

    res.json({
      ok: true,
      dbName,
      readyState,
      usersCount,
      profilesCount,
    });
  } catch (e) {
    log('error', reqId, '🔴 debug-db failed', { message: e.message });
    res.status(500).json({ error: e.message });
  }
});

// GET: Retrieve or auto-create profile (raw)
app.get('/api/profile', authenticateToken, async (req, res) => {
  const reqId = req.reqId;
  await connectDB(reqId);

  try {
    const key = req.userIdentifier;

    log('debug', reqId, '🔎 Looking for UserProfile', { userId: key });
    let profile = await UserProfile.findOne({ userId: key });

    if (!profile) {
      log('warn', reqId, '🆕 Profile not found -> creating', { userId: key });
      profile = await UserProfile.create({ userId: key });
    }

    res.json(profile);
  } catch (error) {
    if (error.code === 11000) {
      log('warn', reqId, '♻️ Duplicate profile race detected -> refetching', { userId: req.userIdentifier });
      const profile = await UserProfile.findOne({ userId: req.userIdentifier });
      return res.json(profile);
    }

    log('error', reqId, '🔴 /api/profile failed', { message: error.message });
    res.status(500).json({ error: error.message });
  }
});

// GET: merged user + profile
app.get('/api/me', authenticateToken, async (req, res) => {
  const reqId = req.reqId;
  await connectDB(reqId);

  try {
    const identifier = req.userIdentifier;

    log('info', reqId, '🧠 /api/me start', { identifier });

    // Try by email first
    let user = await User.findOne({ email: identifier }).lean();
    log('debug', reqId, '🔍 User findOne(email)', { identifier, found: !!user });

    // Fallback: identifier might be mongo _id
    if (!user && mongoose.Types.ObjectId.isValid(identifier)) {
      user = await User.findById(identifier).lean();
      log('debug', reqId, '🔍 User findById fallback', { identifier, found: !!user });
    }

    if (!user) {
      log('warn', reqId, '❌ User not found in users collection', { identifier });
      return res.status(404).json({ message: "User not found", identifierUsed: identifier });
    }

    const userKey = user.email; // normalize profiles by email
    log('info', reqId, '✅ User resolved', { email: userKey, userId: user._id });

    // profile fetch/create
    let profile = await UserProfile.findOne({ userId: userKey }).lean();
    log('debug', reqId, '🔎 UserProfile findOne', { userId: userKey, found: !!profile });

    if (!profile) {
      log('warn', reqId, '🆕 Profile missing -> create', { userId: userKey });
      profile = await UserProfile.create({ userId: userKey });
      profile = profile.toObject();
    }

    // MERGE
    const merged = {
      email: user.email,
      name: user.name || "",
      avatar: user.avatar || "",
      image: user.image || "",
      organization: user.organization || profile.organization || "",
      phone: user.phone || profile.phone || "",
      timezone: profile.timezone || "Africa/Tunis",
      preferences: profile.preferences || {}
    };

    log('info', reqId, '✅ /api/me success', {
      email: merged.email,
      hasProfile: true,
      prefsKeys: Object.keys(merged.preferences || {}),
      notifKeys: Object.keys(merged.preferences?.notifications || {}),
    });

    return res.json(merged);
  } catch (error) {
    log('error', req.reqId, '🔴 /api/me failed', { message: error.message, stack: error.stack });
    return res.status(500).json({ error: error.message });
  }
});

// PUT: update user + profile (merged)
app.put('/api/me', authenticateToken, async (req, res) => {
  const reqId = req.reqId;
  await connectDB(reqId);

  try {
    const identifier = req.userIdentifier;

    log('info', reqId, '🧠 /api/me PUT start', {
      identifier,
      bodyKeys: Object.keys(req.body || {}),
      body: req.body, // remove if too noisy
    });

    // Resolve user first (email or _id)
    let userDoc = await User.findOne({ email: identifier }).lean();
    if (!userDoc && mongoose.Types.ObjectId.isValid(identifier)) {
      userDoc = await User.findById(identifier).lean();
    }
    if (!userDoc) {
      log('warn', reqId, '❌ User not found for update', { identifier });
      return res.status(404).json({ message: "User not found", identifierUsed: identifier });
    }

    const email = userDoc.email;
    log('info', reqId, '✅ User for update resolved', { email, userId: userDoc._id });

    // Allowed updates for users collection
    const userUpdates = {};
    if (typeof req.body.name === "string") userUpdates.name = req.body.name;
    if (typeof req.body.avatar === "string") userUpdates.avatar = req.body.avatar;
    if (typeof req.body.image === "string") userUpdates.image = req.body.image;
    if (typeof req.body.organization === "string") userUpdates.organization = req.body.organization;
    if (typeof req.body.phone === "string") userUpdates.phone = req.body.phone;

    // Allowed updates for userProfiles collection
    const profileUpdates = {};
    if (typeof req.body.timezone === "string") profileUpdates.timezone = req.body.timezone;
    if (req.body.preferences && typeof req.body.preferences === "object") {
      profileUpdates.preferences = req.body.preferences;
    }

    log('debug', reqId, '🧩 Computed updates', { userUpdates, profileUpdates });

    // Update user by email (stable)
    const user = await User.findOneAndUpdate(
      { email },
      { $set: userUpdates },
      { new: true }
    ).lean();

    log('debug', reqId, '✏️ User updated', { updated: !!user });

    // Upsert profile by email
    const profile = await UserProfile.findOneAndUpdate(
      { userId: email },
      { $set: profileUpdates },
      { new: true, upsert: true, runValidators: true }
    ).lean();

    log('debug', reqId, '✏️ Profile upserted', { updated: !!profile });

    const merged = {
      email: user.email,
      name: user.name || "",
      avatar: user.avatar || "",
      image: user.image || "",
      organization: user.organization || profile.organization || "",
      phone: user.phone || profile.phone || "",
      timezone: profile.timezone || "Africa/Tunis",
      preferences: profile.preferences || {}
    };

    log('info', reqId, '✅ /api/me PUT success', {
      email: merged.email,
      notifKeys: Object.keys(merged.preferences?.notifications || {}),
    });

    return res.json(merged);
  } catch (error) {
    log('error', req.reqId, '🔴 /api/me PUT failed', { message: error.message, stack: error.stack });
    return res.status(500).json({ error: error.message });
  }
});

// PUT: raw profile update
app.put('/api/profile', authenticateToken, async (req, res) => {
  const reqId = req.reqId;
  await connectDB(reqId);

  try {
    const updates = { ...req.body };

    delete updates.userId;
    delete updates._id;
    delete updates.createdAt;
    delete updates.updatedAt;

    log('debug', reqId, '✏️ /api/profile updates', { updates });

    const profile = await UserProfile.findOneAndUpdate(
      { userId: req.userIdentifier },
      { $set: updates },
      { new: true, upsert: true, runValidators: true }
    );

    res.json(profile);
  } catch (error) {
    log('error', reqId, '🔴 /api/profile PUT failed', { message: error.message, stack: error.stack });
    res.status(500).json({ error: error.message });
  }
});

// ✅ REQUIRED FOR VERCEL
module.exports = app;
