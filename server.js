const express = require("express");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("./schema/UserSchema");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;
const connection = process.env.CON_STRING;
const SECRET_KEY = process.env.SECRET_KEY || "your_secret_key";

app.use(bodyParser.json());
app.use(cors());

mongoose
    .connect(connection, {
        // useNewUrlParser: true,
        // useUnifiedTopology: true,
    })
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.error("MongoDB connection error:", err));


app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    try {
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Error in registration:", error.message);
        res.status(500).json({ message: "Error registering user" });
    }
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user._id, email: user.email }, SECRET_KEY, {
            expiresIn: "1h",
        });

        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        console.error("Error in login:", error.message);
        res.status(500).json({ message: "Error logging in" });
    }
});


app.get("/protected", (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "Access denied" });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        res.status(200).json({ message: "Protected data", user: decoded });
    } catch (error) {
        console.error("Invalid token:", error.message);
        res.status(401).json({ message: "Invalid token" });
    }
});

app.listen(port, () => console.log(`Listening on localhost ${port}`));