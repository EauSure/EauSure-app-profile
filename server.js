// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

// --- 1. MONGODB CONFIGURATION (Robust Pattern) ---
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URI) throw new Error("❌ MONGO_URI missing");

let cached = global.mongoose;
if (!cached) cached = global.mongoose = { conn: null, promise: null };

async function connectDB() {
  if (cached.conn) return cached.conn;
  if (!cached.promise) {
    cached.promise = mongoose
      .connect(MONGO_URI, {
        bufferCommands: false,
        serverSelectionTimeoutMS: 5000,
      })
      .then((mongoose) => mongoose);
  }
  cached.conn = await cached.promise;
  return cached.conn;
}

// --- 2. THE SCHEMA (Explicit collection + strong uniqueness) ---
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
    collection: 'userProfiles' // 👈 EXACT collection name
  }
);

// 🔐 Enforce 1 profile per user at DB level
UserProfileSchema.index({ userId: 1 }, { unique: true });

const UserProfile =
  mongoose.models.UserProfile ||
  mongoose.model('UserProfile', UserProfileSchema);

// --- 3. MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token missing' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Token invalid' });

    req.userIdentifier = decoded.email || decoded.id;
    if (!req.userIdentifier) {
      return res.status(400).json({ message: 'Invalid token payload' });
    }

    next();
  });
};

// --- 4. API ROUTES ---

// GET: Retrieve or auto-create profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  await connectDB();
  try {
    let profile = await UserProfile.findOne({ userId: req.userIdentifier });

    if (!profile) {
      profile = await UserProfile.create({ userId: req.userIdentifier });
    }

    res.json(profile);
  } catch (error) {
    // Handles rare duplicate race condition gracefully
    if (error.code === 11000) {
      const profile = await UserProfile.findOne({ userId: req.userIdentifier });
      return res.json(profile);
    }

    res.status(500).json({ error: error.message });
  }
});

// PUT: Update profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  await connectDB();
  try {
    const updates = { ...req.body };

    // Prevent immutable fields
    delete updates.userId;
    delete updates._id;
    delete updates.createdAt;
    delete updates.updatedAt;

    const profile = await UserProfile.findOneAndUpdate(
      { userId: req.userIdentifier },
      { $set: updates },
      {
        new: true,
        upsert: true,
        runValidators: true
      }
    );

    res.json(profile);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ REQUIRED FOR VERCEL
module.exports = app;
