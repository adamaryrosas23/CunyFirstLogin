// ---------------------- IMPORTS ----------------------
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cors = require("cors");
const nodemailer = require("nodemailer");
const Users = require("./models/User");
require("dotenv").config();

const twilio = require("twilio")(process.env.TWILIO_SID, process.env.TWILIO_AUTH);

// ---------------------- APP SETUP ----------------------
const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));

// ---------------------- DATABASE ----------------------
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.error("MongoDB error:", err));

// ---------------------- MODELS ----------------------
const UserSchema = new mongoose.Schema({
    fullName: String,
    email: String,
    password: String,
    phone: String,

    mfaEnabled: { type: Boolean, default: true },

    fingerprint: String,
    lastLocation: Object,
    lastRisk: String,

    tempOTP: String,
    tempToken: String,
    otpExpires: Date
});

const LoginEventSchema = new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    timestamp: { type: Date, default: Date.now },
    location: Object,
    fpMatch: Boolean,
    geoScore: Number,
    geoRisk: String,
    mfaRequired: Boolean
});

const LoginEvent = mongoose.model("LoginEvent", LoginEventSchema);

// ---------------------- HELPERS ----------------------
function signAuthToken(id) {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "7d" });
}

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function hashFingerprint(fp) {
    return crypto.createHash("sha256").update(fp).digest("hex");
}
function safeLocation(loc) {
    if (!loc || typeof loc !== "object") {
        return {
            city: "Unknown",
            region: "",
            country: "",
            latitude: 0,
            longitude: 0
        };
    }

    return {
        city: loc.city || "Unknown",
        region: loc.region || "",
        country: loc.country || "",
        latitude: Number(loc.latitude) || 0,
        longitude: Number(loc.longitude) || 0
    };
}


// Haversine distance
function geoDistance(loc1, loc2) {
    if (!loc1 || !loc2) return 0;

    const R = 6371;
    const dLat = (loc2.latitude - loc1.latitude) * Math.PI / 180;
    const dLon = (loc2.longitude - loc1.longitude) * Math.PI / 180;

    const a =
        Math.sin(dLat/2) ** 2 +
        Math.cos(loc1.latitude * Math.PI/180) *
        Math.cos(loc2.latitude * Math.PI/180) *
        Math.sin(dLon/2) ** 2;

    return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function computeGeoRisk(lastLoc, newLoc) {
    if (!lastLoc) return 0;

    const km = geoDistance(lastLoc, newLoc);

    if (km < 50) return 5;
    if (km < 200) return 20;
    if (km < 1000) return 40;
    if (km < 3000) return 60;
    if (km < 7000) return 80;
    return 100;
}

function geoRiskLabel(score) {
    if (score >= 70) return "high";
    if (score >= 30) return "medium";
    return "normal";
}

function sendOtpWhatsApp(to, otp) {
    return twilio.messages.create({
        from: process.env.TWILIO_WHATSAPP_FROM,
        to: `whatsapp:${to.replace(/\s+/g, "")}`,
        body: `Your verification code is: ${otp}`
    });
}

const mailer = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

function sendOtpEmail(to, otp) {
    return mailer.sendMail({
        from: `"Security Team" <${process.env.EMAIL_USER}>`,
        to,
        subject: "Your Verification Code",
        text: `Your verification code is: ${otp}`,
        html: `<p>Your verification code is:</p>
               <h2 style="font-size:28px; letter-spacing:4px;">${otp}</h2>`
    });
}


// ---------------------- CLEANUP FUNCTION ----------------------
async function cleanupLoginEvents(userId) {
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);

    await LoginEvent.deleteMany({
        userId,
        timestamp: { $lt: twoDaysAgo }
    });

    const events = await LoginEvent.find({ userId }).sort({ timestamp: -1 });

    if (events.length > 10) {
        const idsToDelete = events.slice(10).map(e => e._id);
        await LoginEvent.deleteMany({ _id: { $in: idsToDelete } });
    }
}

// ---------------------- AUTH MIDDLEWARE ----------------------
function authMiddleware(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.json({ valid: false });

    const token = header.split(" ")[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch {
        return res.json({ valid: false });
    }
}

// ---------------------- ROUTES ----------------------

// REGISTER
app.post("/api/register", async (req, res) => {
    const { fullName, email, password, phone, mfaEnabled } = req.body;

    const exists = await Users.findOne({ email });
    if (exists) return res.json({ status: "error", message: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);

    await Users.create({
        fullName,
        email,
        password: hashed,
        phone,
        mfaEnabled
    });

    res.json({ status: "ok" });
});

// LOGIN
app.post("/api/login", async (req, res) => {
    try {
        const { email, password, location } = req.body;
const normalizedLocation = safeLocation(location);

        const user = await Users.findOne({ email });
        if (!user) return res.json({ status: "error", message: "Invalid login" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.json({ status: "error", message: "Invalid login" });

        if (!user.mfaEnabled) {
            const authToken = signAuthToken(user._id);
            user.lastLocation = normalizedLocation;
            
            await LoginEvent.create({
                userId: user._id,
                location: normalizedLocation,
                fpMatch: true,
                geoScore: 0,
                geoRisk: "normal",
                mfaRequired: false
            });

            await cleanupLoginEvents(user._id);

            return res.json({
                status: "ok",
                token: authToken
            });
        }

        const otp = generateOTP();
        user.tempOTP = otp;
        user.tempToken = crypto.randomBytes(20).toString("hex");
        user.otpExpires = Date.now() + 5 * 60 * 1000;
        await user.save();

        if (user.phone) sendOtpWhatsApp(user.phone, otp);
        if (user.email) sendOtpEmail(user.email, otp);
        return res.json({
            status: "mfa_required",
            token: user.tempToken
        });

    } catch (err) {
        console.error("Login error:", err);
        res.json({ status: "error", message: "Login failed" });
    }
});

// MFA VERIFY
app.post("/api/mfa-verify", async (req, res) => {
    const { token, code, fingerprint, location } = req.body;

    const user = await Users.findOne({ tempToken: token });
    if (!user) return res.json({ status: "error", message: "Invalid session" });

    if (user.tempOTP !== code) {
        return res.json({ status: "error", message: "Invalid code" });
    }

    user.fingerprint = hashFingerprint(fingerprint);
    user.lastLocation = safeLocation(location);
    user.lastRisk = "normal";
    user.tempOTP = null;
    user.tempToken = null;

    await user.save();

    const authToken = signAuthToken(user._id);

    await LoginEvent.create({
        userId: user._id,
        location: safeLocation(location),
        fpMatch: true,
        geoScore: 0,
        geoRisk: "normal",
        mfaRequired: true
    });

    await cleanupLoginEvents(user._id);

    res.json({ status: "ok", token: authToken });
});

// VERIFY SESSION
app.post("/api/verify-session", authMiddleware, async (req, res) => {
    try {
        const { fingerprint, location } = req.body;
        const normalizedLocation = safeLocation(location);
        const user = await Users.findById(req.userId);
        if (!user) return res.json({ valid: false });

        if (!user.mfaEnabled) {
            return res.json({
                valid: true,
                fpMatch: true,
                geoScore: 0,
                geoRisk: "normal",
                risk: "normal"
            });
        }

        const fpMatch = hashFingerprint(fingerprint) === user.fingerprint;
        const geoScore = computeGeoRisk(user.lastLocation, normalizedLocation);
        const geoRisk = geoRiskLabel(geoScore);

        const valid = fpMatch && geoScore < 70;

        res.json({
            valid,
            fpMatch,
            geoScore,
            geoRisk,
            risk: geoRisk
        });

    } catch (err) {
        console.error("Verify session error:", err);
        res.json({ valid: false });
    }
});
let resetCodes = {}; // store temporary OTPs

app.post("/api/send-reset-code", async (req, res) => {
    const { email } = req.body;

    const user = await Users.findOne({ email });
    if (!user) return res.json({ status: "error", message: "Email not found" });

    const code = crypto.randomInt(100000, 999999).toString();
    resetCodes[email] = code;
    
    // SEND EMAIL
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your Password Reset Code",
        text: `Your reset code is: ${code}`
    });

    res.json({ status: "ok", message: "Reset code sent to your email" });
});

    app.post("/api/verify-reset-code", (req, res) => {
    const { email, code } = req.body;

    if (resetCodes[email] !== code) {
        return res.json({ status: "error", message: "Invalid code" });
    }

    res.json({ status: "ok", message: "Code verified" });
});

app.post("/api/reset-password", async (req, res) => {
    const { email, newPass } = req.body;

    const hashed = await bcrypt.hash(newPass, 10);
    await Users.updateOne(
        { email },
        { password: hashed }
    );

    delete resetCodes[email];

    res.json({ status: "ok", message: "Password updated successfully" });
});





// TOGGLE MFA
app.post("/api/toggle-mfa", authMiddleware, async (req, res) => {
    const user = await Users.findById(req.userId);
    if (!user) return res.json({ status: "error" });

    user.mfaEnabled = !user.mfaEnabled;
    await user.save();

    res.json({
        status: "ok",
        mfaEnabled: user.mfaEnabled
    });
});

// CLEAR LOGS
app.post("/api/clear-logs", authMiddleware, async (req, res) => {
    await LoginEvent.deleteMany({ userId: req.userId });
    res.json({ status: "ok" });
});

// USER INFO
app.get("/api/user-info", authMiddleware, async (req, res) => {
    const user = await Users.findById(req.userId);

    res.json({
        email: user.email,
        mfaEnabled: user.mfaEnabled,
        fingerprint: user.fingerprint,
        lastLocation: user.lastLocation,
        lastRisk: user.lastRisk
    });
});

// LOGIN HISTORY
app.get("/api/login-history", authMiddleware, async (req, res) => {
    await cleanupLoginEvents(req.userId);

    const events = await LoginEvent.find({ userId: req.userId }).sort({ timestamp: 1 });
    res.json(events);
});

// SIMULATOR
app.post("/api/simulate-login", authMiddleware, async (req, res) => {
    try {
        const { spoofLocation, spoofFingerprint, mode } = req.body;
        const normalizedSpoof = safeLocation(spoofLocation);
        const user = await Users.findById(req.userId);
        if (!user) return res.json({ status: "error", message: "User not found" });

        const fpMatch = (mode === "trusted")
            ? hashFingerprint(spoofFingerprint) === user.fingerprint
            : false;

        const geoScore = computeGeoRisk(user.lastLocation, normalizedSpoof);
        const geoRisk = geoRiskLabel(geoScore);

        let action = "allow";
        let mfaRequired = false;

        if (geoScore >= 70 && !fpMatch) {
            action = "block";
        } else if (geoScore >= 30 || !fpMatch) {
            action = "otp";
            mfaRequired = true;
        }

        await LoginEvent.create({
            userId: user._id,
            location: normalizedSpoof,
            fpMatch,
            geoScore,
            geoRisk,
            mfaRequired
        });

        await cleanupLoginEvents(req.userId);

        res.json({
            status: "ok",
            action,
            fpMatch,
            geoScore,
            geoRisk,
            mfaRequired
        });

    } catch (err) {
        console.error("Simulator error:", err);
        res.json({ status: "error", message: "Simulation failed" });
    }
});

// ---------------------- START SERVER ----------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

