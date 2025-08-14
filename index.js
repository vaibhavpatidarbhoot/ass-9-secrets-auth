require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const validator = require("validator");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change_me";
const NODE_ENV = process.env.NODE_ENV || "development";

// --- MongoDB ---
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err.message));

// --- User Model ---
const userSchema = new mongoose.Schema(
  {
    name: { type: String, trim: true, required: true, minlength: 2 },
    email: { type: String, trim: true, unique: true, required: true },
    password: { type: String, required: true } // hashed
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

// --- App Middleware ---
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Optional session to demonstrate secure, HttpOnly cookies for session ids
app.use(
  session({
    secret: process.env.SESSION_SECRET || "session_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: NODE_ENV === "production" // true on HTTPS (Render uses HTTPS)
    }
  })
);

// --- Helpers ---
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,8}$/;

function setAuthCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: NODE_ENV === "production",
    maxAge: 60 * 60 * 1000
  });
}

function verifyToken(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.redirect("/login?msg=Please%20login%20first");

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.redirect("/login?msg=Session%20expired.%20Please%20login%20again");
    req.userId = decoded.id;
    next();
  });
}

// --- Routes ---
app.get("/", (req, res) => res.redirect("/login"));

app.get("/register", (req, res) => {
  res.render("register", { msg: req.query.msg || null });
});

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Basic field presence
    if (!name || !email || !password) {
      return res.redirect("/register?msg=All%20fields%20are%20required");
    }

    // Email format
    if (!validator.isEmail(email)) {
      return res.redirect("/register?msg=Invalid%20email%20format");
    }

    // Password format
    if (!passwordRegex.test(password)) {
      return res.redirect(
        "/register?msg=Password%20must%20have%20lowercase,%20uppercase,%20number,%20and%20be%206-8%20chars"
      );
    }

    // Unique email
    const exists = await User.findOne({ email });
    if (exists) {
      return res.redirect("/register?msg=Email%20already%20registered");
    }

    const hash = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hash });

    // After Registration → redirect to login
    return res.redirect("/login?msg=Registration%20successful.%20Please%20login");
  } catch (err) {
    console.error(err);
    return res.redirect("/register?msg=Something%20went%20wrong");
  }
});

app.get("/login", (req, res) => {
  res.render("login", { msg: req.query.msg || null });
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic presence
    if (!email || !password) {
      return res.redirect("/login?msg=Email%20and%20password%20are%20required");
    }

    // Email format
    if (!validator.isEmail(email)) {
      return res.redirect("/login?msg=Invalid%20email%20format");
    }

    // Password format check (to guide user)
    if (!passwordRegex.test(password)) {
      return res.redirect(
        "/login?msg=Password%20format:%20lowercase,%20uppercase,%20number,%206-8%20chars"
      );
    }

    const user = await User.findOne({ email });
    if (!user) return res.redirect("/login?msg=User%20not%20found");

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.redirect("/login?msg=Incorrect%20password");

    setAuthCookie(res, { id: user._id });
    return res.redirect("/secrets");
  } catch (err) {
    console.error(err);
    return res.redirect("/login?msg=Login%20failed");
  }
});

app.get("/secrets", verifyToken, async (req, res) => {
  const user = await User.findById(req.userId).lean();
  if (!user) return res.redirect("/login?msg=Please%20login%20again");
  res.render("secrets", { user });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    sameSite: "lax",
    secure: NODE_ENV === "production"
  });
  res.redirect("/login?msg=Logged%20out%20successfully");
});

app.use((req, res) => res.status(404).send("404 Not Found"));

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
