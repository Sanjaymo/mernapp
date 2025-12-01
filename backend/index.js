
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");

const app = express();

// ======= CONFIG =======
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ======= MIDDLEWARES =======
const allowedOrigins = [
  "http://localhost:3000",
  "https://mern-todo-app-mu-three.vercel.app",
  "https://mern-todo-app-bzmljkh10-sanjay-choudharis-projects.vercel.app",
  "https://mern-todo-app-git-main-sanjay-choudharis-projects.vercel.app",
];

app.use(
  cors({
    origin(origin, callback) {
      // Allow tools / server-to-server (no Origin header)
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      console.log("❌ Blocked by CORS:", origin);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

// (optional but helpful)
app.options("*", cors());
app.use(express.json());

// ======= DB CONNECTION =======
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// ======= MODELS =======
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String }, // hashed or empty for Google accounts
    provider: { type: String, default: "local" }, // local | google
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

const todoSchema = new mongoose.Schema(
  {
    text: { type: String, required: true },
    done: { type: Boolean, default: false },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

const Todo = mongoose.model("Todo", todoSchema);

// ======= AUTH MIDDLEWARE =======
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.userId = payload.id;
    next();
  });
}

// ======= HELPERS =======
function issueToken(user) {
  return jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
}

// ======= ROUTES =======

app.get("/", (req, res) => {
  res.json({ message: "Backend API is working ✅" });
});

// --- Auth: Register (email/password) ---
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: "Name, email and password are required" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: "Email already in use" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashed,
      provider: "local",
    });

    const token = issueToken(user);

    res.status(201).json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Failed to register user" });
  }
});

// --- Auth: Login (email/password) ---
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email, provider: "local" });
    if (!user) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const token = issueToken(user);

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Failed to login" });
  }
});

// --- Auth: Google login ---
app.post("/api/auth/google", async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) {
      return res.status(400).json({ error: "No Google token provided" });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name || email.split("@")[0];

    let user = await User.findOne({ email, provider: "google" });

    if (!user) {
      user = await User.create({
        name,
        email,
        provider: "google",
        password: "", // not used for google accounts
      });
    }

    const token = issueToken(user);

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Google auth error:", err);
    res.status(500).json({ error: "Failed to login with Google" });
  }
});

// --- Todos (protected) ---
// get all todos for logged in user
app.get("/api/todos", auth, async (req, res) => {
  try {
    const todos = await Todo.find({ owner: req.userId }).sort({
      createdAt: -1,
    });
    res.json(todos);
  } catch (err) {
    console.error("GET /api/todos error:", err);
    res.status(500).json({ error: "Failed to fetch todos" });
  }
});

// create new todo
app.post("/api/todos", auth, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: "Text is required" });

    const todo = await Todo.create({
      text,
      owner: req.userId,
    });

    res.status(201).json(todo);
  } catch (err) {
    console.error("POST /api/todos error:", err);
    res.status(500).json({ error: "Failed to create todo" });
  }
});

// delete todo
app.delete("/api/todos/:id", auth, async (req, res) => {
  try {
    const { id } = req.params;

    const deleted = await Todo.findOneAndDelete({
      _id: id,
      owner: req.userId,
    });

    if (!deleted) {
      return res.status(404).json({ error: "Todo not found" });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("DELETE /api/todos error:", err);
    res.status(500).json({ error: "Failed to delete todo" });
  }
});

// ======= START SERVER =======
app.listen(PORT, () => {
  console.log(`Server running at http://127.0.0.1:${PORT}`);
});



