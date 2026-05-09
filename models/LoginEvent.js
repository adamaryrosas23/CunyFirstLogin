const mongoose = require("mongoose");

const LoginEventSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  fingerprint: String,
  location: {
    city: String,
    region: String,
    country: String,
    latitude: Number,
    longitude: Number
  },
  geoScore: Number,
  geoRisk: String,
  fpMatch: Boolean,
  mfaRequired: Boolean,
  success: Boolean,
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model("LoginEvent", LoginEventSchema);
