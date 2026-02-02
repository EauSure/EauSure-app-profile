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
    cached.promise = mongoose.connect(MONGO_URI, {
      bufferCommands: false,
      serverSelectionTimeoutMS: 5000,
    }).then((mongoose) => mongoose);
  }
  cached.conn = await cached.promise;
  return cached.conn;
}

// --- 2. THE SCHEMA (Matches your JSON strictly) ---
const UserProfileSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true }, // Stores email or Auth ID
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
}, { 
  timestamps: true // Automatically handles createdAt and updatedAt
});

const UserProfile = mongoose.model('UserProfile', UserProfileSchema);

// --- 3. MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token missing' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Token invalid' });
    // Assuming your Auth API puts 'email' or 'id' in the token
    req.userIdentifier = decoded.email || decoded.id; 
    next();
  });
};

// --- 4. API ROUTES ---

// GET: Retrieve Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  await connectDB();
  try {
    let profile = await UserProfile.findOne({ userId: req.userIdentifier });

    if (!profile) {
      // Auto-create empty profile if it doesn't exist yet
      profile = await UserProfile.create({ userId: req.userIdentifier });
    }

    res.json(profile);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT: Update Settings
app.put('/api/profile', authenticateToken, async (req, res) => {
  await connectDB();
  try {
    const updates = req.body;
    
    // Prevent updating userId or _id manually
    delete updates.userId;
    delete updates._id;
    delete updates.createdAt;

    const profile = await UserProfile.findOneAndUpdate(
      { userId: req.userIdentifier },
      { $set: updates },
      { new: true, upsert: true, runValidators: true } // Returns the updated document
    );

    res.json(profile);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));