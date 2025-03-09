require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const Joi = require('joi');
const morgan = require('morgan');
const helmet = require('helmet');

const app = express();

// ✅ ALLOWED ORIGINS (For Web & Mobile)
const allowedOrigins = [
    'https://mern-frontend-registration.vercel.app', // Vercel frontend
    'http://localhost:3000', // Local frontend (for testing)
    'http://localhost', // Android Emulator
    'capacitor://localhost', // Capacitor Android App
    'http://192.168.1.100:5000', // Mobile devices in local network (Replace with your actual IP)
    'http://192.168.1.101:5000'  // Another possible local IP (for testing)
];

// ✅ CORS CONFIGURATION
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.log("❌ CORS BLOCKED:", origin); // Debugging
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// ✅ CORS FIX: Allow OPTIONS Preflight Requests
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
        return res.sendStatus(200);
    }
    
    next();
});

// ✅ Middlewares
app.use(bodyParser.json());
app.use(morgan('dev'));
app.use(helmet());

// ✅ MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connected to MongoDB"))
    .catch(err => console.error("❌ MongoDB connection error:", err));

// ✅ User Model
const User = require('./models/User');

// ✅ Validation Schemas
const registerSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
});

// ✅ REGISTER Endpoint
app.post('/register', async (req, res) => {
    const { error } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ message: "Error registering user" });
    }
});

// ✅ LOGIN Endpoint
app.post('/login', async (req, res) => {
    const { error } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: "User not found" });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: "Invalid password" });

        // ✅ Remember Me Feature
        const rememberMe = req.body.rememberMe || false;
        const expiresIn = rememberMe ? '7d' : '1h'; 

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn });
        res.status(200).json({ token, name: user.name });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Error logging in" });
    }
});

// ✅ ERROR HANDLING MIDDLEWARE
app.use((err, req, res, next) => {
    console.error("Server error:", err.stack);
    res.status(500).json({ message: "Internal server error" });
});

// ✅ START SERVER
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
