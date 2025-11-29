import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import cors from "cors";

const app = express();
const { Pool } = pg;

app.use(cors());
app.use(express.json());

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "postgres",
  password: "1234",
  port: 5432,
});

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const check = await pool.query("SELECT * FROM users_for_english_site WHERE email=$1", [email]);
    if (check.rows.length > 0) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users_for_english_site (username, email, password_hash) VALUES ($1, $2, $3)",
      [username, email, hashed]
    );

    res.json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await pool.query("SELECT * FROM users_for_english_site WHERE email=$1", [email]);
    if (user.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const valid = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ message: "Invalid password" });
    }

    res.json({
      message: "Login successful",
      user: {
        username: user.rows[0].username,
        email: user.rows[0].email
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.listen(3000, () => console.log("Server running on http://localhost:3000"));
