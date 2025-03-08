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

// app.use(cors({ origin: 'http://localhost:3000' }));
const corsOptions = {
    origin: 'http://localhost:5173',  // Allow only your frontend origin
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
};

app.use(cors(corsOptions));

// app.use(cors({ origin: '*' }));


app.use(bodyParser.json());
app.use(morgan('dev'));
app.use(helmet());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});

mongoose.connection.once('open', () => {
    console.log('Connected to MongoDB');
});

// User model
const User = require('./models/User');

// Validation schemas
const registerSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
});

// Register endpoint
app.post('/register', async (req, res) => {
    const { error } = registerSchema.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.status(201).send('User registered');
    } catch (error) {
        res.status(500).send('Error registering user');
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { error } = loginSchema.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('User not found');

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).send('Invalid password');

        // Check if "Remember Me" is selected (frontend se flag aayega)
        const rememberMe = req.body.rememberMe || false;
        const expiresIn = rememberMe ? '7d' : '1h'; // 7 days or 1 hour

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn });
        const response = { token, name: user.name }; // Prepare response
        console.log('Backend Response:', response); // Debugging
        res.header('auth-token', token).send(response);
    } catch (error) {
        res.status(500).send('Error logging in');
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});