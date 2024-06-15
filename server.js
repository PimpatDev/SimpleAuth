const express = require('express');
const connection = require('./db');
const app = express();
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const port = 3000;
dotenv.config(); // Load environment variables from .env file
const saltRounds = parseInt(process.env.SALT_ROUND);
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 15*60*1000,
    max: 5,
});
app.use(bodyParser.json()); // Middleware to parse JSON bodies

const jwt = require('jsonwebtoken');
const secretKey = process.env.SECRET_KEY;

//signup
app.post('/api/auth/signup', limiter, async (req, res) => {
    const { username, firstname, lastname, password, email } = req.body;
    // Input validation
    if (!username || !password || !firstname || !lastname || !email) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds); // Hash the password
        // SQL query to insert a new user
        const query = 'INSERT INTO Users (username, firstname, lastname, hashedPassword, email) VALUES (?, ?, ?, ?, ?)';
        // Execute the query
        connection.query(query, [username, firstname, lastname, hashedPassword, email], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    // Handle duplicate entry error (e.g., username or email already exists)
                    return res.status(409).json({ error: 'Username or email already exists' });
                }
                // General server error
                console.error('Error inserting user:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }
            console.log(`User ${username} created successfully`);// Log the result of the query
            res.status(201).json({ message: `User ${username} created successfully`});// Success
        });
    } catch (err) {
        // Error hashing the password or other unexpected error
        console.error('Error during user creation:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//signup
app.post('/api/auth/signin', limiter,  async (req, res) => {
    const { username, password } = req.body;
    // Input validation
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    const query = 'SELECT * FROM Users WHERE username = ?';
    connection.query(query, [username], async (err, result) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        if (result.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' }); // User not found
        }
        const user = result[0];
        try {
            const passwordMatch = await bcrypt.compare(password, user.hashedPassword);
            if (!passwordMatch) {
                // Passwords do not match
                return res.status(401).json({ error: 'Invalid username or password' });
            }
            // Generate token
            const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, secretKey, {
                expiresIn: '1h'
            });
            // Successful login
            res.status(200).json({ message: 'Login successful', token });
        } catch (err) {
            console.error('Error comparing passwords:', err);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
});

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ message: 'Token is required' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        req.user = decoded;
        next();
    })
}

app.get('/', (req, res) => {
    res.send('Hello world!');
});

app.get('/api/test/all', (req, res) => {
    res.status(200).json({ message: 'Public content' });
});

app.get('/api/test/user', verifyToken, (req, res) => {
    res.status(200).json({ message: 'User content' });
});

app.get('/api/test/admin', verifyToken, (req, res) => {
    if (req.user.role === 'admin') {
        res.status(200).json({ message: 'Admin content' });
    }
    else {
        res.status(403).json({ message: 'Require admin role' });
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
});