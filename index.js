// server.js
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const passport = require("passport");
const passportJWT = require("passport-jwt");
const { Strategy, ExtractJwt } = passportJWT;
const env = require("dotenv").config();

const mongoURI = process.env.MONGODB_URI;

const app = express();
const port = process.env.PORT || 3001;

// Replace 'YOUR_MONGODB_URI' with your actual MongoDB connection string
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;

db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});


app.use(bodyParser.json());
app.use(cors());
app.get("/", (req, res) => {
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.send("Server is running");
});

const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = mongoose.model("UserNew", UserSchema);

const SalarySchema = new mongoose.Schema({
  date: Date,
  hoursWorked: Number,
  hourlyRate: Number,
  employmentType: String,
  userId: String, // Associate salaries with users
});

const Salary = mongoose.model("Salary", SalarySchema);

// Configure Passport
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET, // Replace with your secret key
};

passport.use(
  new Strategy(jwtOptions, async (payload, done) => {
    try {
      const user = await User.findById(payload.id);
      if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    } catch (error) {
      return done(error, false);
    }
  })
);

app.use(passport.initialize());
// Get user data
app.get(
  "/api/user",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const user = await User.findById(req.user._id).select("-password");
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      res.status(200).json(user);
    } catch (error) {
      console.error("Error fetching user data:", error);
      res.status(500).json({ message: "An error occurred" });
    }
  }
);

// Register a new user
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if the username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "An error occurred" });
  }
});

// Login route
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Authentication failed" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Authentication failed" });
    }

    const token = jwt.sign({ id: user._id }, jwtOptions.secretOrKey, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "An error occurred" });
  }
});

// Create a new salary entry
app.post(
  "/api/salaries",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { date, hoursWorked, hourlyRate, employmentType } = req.body;

      // Check if a salary entry with the same date already exists for the user
      const existingSalary = await Salary.findOne({
        userId: req.user._id,
        date,
      });

      if (existingSalary) {
        return res
          .status(400)
          .json({ message: "Salary for this date already exists" });
      }

      const newSalary = new Salary({
        date,
        hoursWorked,
        hourlyRate,
        employmentType,
        userId: req.user._id,
      });

      await newSalary.save();
      res.status(201).json({ message: "Salary added successfully" });
    } catch (error) {
      console.error("Error adding salary:", error);
      res.status(500).json({ message: "An error occurred" });
    }
  }
);

// Get all salaries for the authenticated user
app.get(
  "/api/salaries",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const salaries = await Salary.find({ userId: req.user._id });
      res.json(salaries);
    } catch (error) {
      console.error("Error fetching salaries:", error);
      res.status(500).json({ message: "An error occurred" });
    }
  }
);

// Delete a salary entry
app.delete(
  "/api/salaries/:id",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const salaryId = req.params.id;
    try {
      const deletedSalary = await Salary.findByIdAndDelete(salaryId);
      if (!deletedSalary) {
        res.status(404).json({ message: "Salary not found" });
      } else {
        res.json({ message: "Salary deleted successfully" });
      }
    } catch (error) {
      console.error("Error deleting salary:", error);
      res.status(500).json({ message: "An error occurred" });
    }
  }
);

//Delete full entry

app.delete(
  "/api/salaries",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      // Delete all salary entries for the authenticated user
      await Salary.deleteMany({ userId: req.user._id });
      res.json({ message: "All salary entries deleted successfully" });
    } catch (error) {
      console.error("Error deleting salary entries:", error);
      res.status(500).json({ message: "An error occurred" });
    }
  }
);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
