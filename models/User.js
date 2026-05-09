const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  fullName: String,
  email: { type: String, unique: true },
  password: String,          // ← FIXED
  phone: String,

  mfaEnabled: { type: Boolean, default: true },

  fingerprint: String,
  lastLocation: Object,
  lastRisk: String,

  tempOTP: String,
  tempToken: String,
  otpExpires: Date,

  resetOtp: String,
  resetOtpExpires: Date,
  resetOtpVerified: Boolean
});

module.exports =
  mongoose.models.User || mongoose.model("User", UserSchema);
