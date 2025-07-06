// server.js (main backend file)

// Import necessary packages
import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import bcrypt from 'bcryptjs'; // For password hashing
import jwt from 'jsonwebtoken'; // For JSON Web Tokens

// Load environment variables from .env file
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(express.json()); // For parsing application/json
// IMPORTANT: Configure CORS to specifically allow your Vercel frontend URL
app.use(cors({
    origin: 'https://hotel-review-self.vercel.app', // Your Vercel frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// --- Database Connection ---
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/ratingapp';

mongoose.connect(MONGODB_URI)
    .then(() => console.log('MongoDB connected successfully!'))
    .catch(err => console.error('MongoDB connection error:', err));

// --- Mongoose Schemas ---

// Hotel/Restaurant Schema
const hotelSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    location: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        trim: true
    },
    imageUrl: {
        type: String,
        default: 'https://placehold.co/400x250/CCCCCC/333333?text=Hotel+Image'
    },
}, { timestamps: true });

const Hotel = mongoose.model('Hotel', hotelSchema);

// User Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: { // This will store hashed passwords
        type: String,
        required: true
    },
    isAdmin: {
        type: Boolean,
        default: false
    }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// --- JWT Secret ---
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey'; // Use a strong, random key in production!

// --- Middleware for Authentication (JWT Verification) ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) {
        return res.status(401).json({ message: 'Authentication token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user; // Attach user payload to request
        next();
    });
};

// --- Middleware for Admin Authorization ---
const authorizeAdmin = (req, res, next) => {
    // Check if req.user exists and if req.user.isAdmin is true
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ message: 'Access denied: Admin privileges required' });
    }
    next();
};

// --- API Routes ---

// Test route
app.get('/', (req, res) => {
    res.send('Rating App Backend is running!');
});

// TEMPORARY: Route to create an admin user for testing
app.post('/api/seed-admin', async (req, res) => {
    try {
        const adminEmail = 'admin@example.com';
        let adminUser = await User.findOne({ email: adminEmail });

        if (adminUser) {
            return res.status(200).json({ message: 'Admin user already exists.' });
        }

        const hashedPassword = await bcrypt.hash('adminpassword', 10); // Use a strong password!
        adminUser = new User({
            username: 'admin',
            email: adminEmail,
            password: hashedPassword,
            isAdmin: true // This is the crucial part
        });

        await adminUser.save();
        res.status(201).json({ message: 'Admin user created successfully!', user: adminUser });
    } catch (error) {
        console.error('Error seeding admin user:', error);
        res.status(500).json({ message: 'Failed to seed admin user', error: error.message });
    }
});


// Route to get all hotels (publicly accessible)
app.get('/api/hotels', async (req, res) => {
    try {
        const hotels = await Hotel.find({});
        res.status(200).json(hotels);
    } catch (error) {
        console.error('Error fetching hotels:', error);
        res.status(500).json({ message: 'Failed to fetch hotels', error: error.message });
    }
});

// Route to add a new hotel (Admin protected)
app.post('/api/hotels', authenticateToken, authorizeAdmin, async (req, res) => {
    const { name, location, description, imageUrl } = req.body;
    if (!name || !location) {
        return res.status(400).json({ message: 'Hotel name and location are required.' });
    }
    try {
        const newHotel = new Hotel({ name, location, description, imageUrl });
        await newHotel.save();
        res.status(201).json({ message: 'Hotel added successfully!', hotel: newHotel });
    } catch (error) {
        console.error('Error adding hotel:', error);
        if (error.code === 11000) { // Duplicate key error
            return res.status(409).json({ message: 'A hotel with this name already exists.' });
        }
        res.status(500).json({ message: 'Failed to add hotel', error: error.message });
    }
});

// Route to update a hotel (Admin protected)
app.put('/api/hotels/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, location, description, imageUrl } = req.body;
    try {
        const updatedHotel = await Hotel.findByIdAndUpdate(
            id,
            { name, location, description, imageUrl },
            { new: true, runValidators: true }
        );
        if (!updatedHotel) {
            return res.status(404).json({ message: 'Hotel not found.' });
        }
        res.status(200).json({ message: 'Hotel updated successfully!', hotel: updatedHotel });
    } catch (error) {
        console.error('Error updating hotel:', error);
        res.status(500).json({ message: 'Failed to update hotel', error: error.message });
    }
});

// Route to delete a hotel (Admin protected)
app.delete('/api/hotels/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const deletedHotel = await Hotel.findByIdAndDelete(id);
        if (!deletedHotel) {
            return res.status(404).json({ message: 'Hotel not found.' });
        }
        // Optionally, delete all reviews associated with this hotel
        // await Review.deleteMany({ hotel: id }); // If you have a Review model
        res.status(200).json({ message: 'Hotel deleted successfully!' });
    } catch (error) {
        console.error('Error deleting hotel:', error);
        res.status(500).json({ message: 'Failed to delete hotel', error: error.message });
    }
});

// --- Authentication Routes ---

// User Registration
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Please enter all fields' });
    }

    try {
        // Check if user already exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User with that email already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        user = new User({
            username,
            email,
            password: hashedPassword
        });

        await user.save();

        res.status(201).json({ message: 'User registered successfully!' });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration', error: error.message });
    }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Please enter all fields' });
    }

    try {
        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Validate password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate JWT
        const payload = {
            user: { // This payload structure is what authenticateToken middleware receives
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.isAdmin // Ensure isAdmin is correctly included in the JWT payload
            }
        };

        jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: '1h' }, // Token expires in 1 hour
            (err, token) => {
                if (err) throw err;
                res.json({
                    message: 'Logged in successfully!',
                    token, // The actual JWT token string
                    user: { // The user object to be sent to the frontend
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        isAdmin: user.isAdmin // Ensure isAdmin is correctly included in the response body
                    }
                });
            }
        );

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login', error: error.message });
    }
});

// --- Analytics Routes (Admin Protected) ---
// You will need a Review model and actual reviews in your DB for these to return meaningful data.

// Overall Analytics
app.get('/api/analytics/overall', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const totalHotels = await Hotel.countDocuments();
        const totalUsers = await User.countDocuments();
        // Assuming you have a Review model
        // const totalReviews = await Review.countDocuments();
        // const avgRatingResult = await Review.aggregate([
        //     { $group: { _id: null, averageRating: { $avg: '$rating' } } }
        // ]);
        // const averageRating = avgRatingResult.length > 0 ? avgRatingResult[0].averageRating.toFixed(2) : 0;

        // Placeholder data if Review model is not yet implemented or no reviews exist
        const totalReviews = 0;
        const averageRating = 0;

        res.json({ totalHotels, totalUsers, totalReviews, averageRating });
    } catch (error) {
        console.error('Error fetching overall analytics:', error);
        res.status(500).json({ message: 'Failed to fetch overall analytics', error: error.message });
    }
});

// Reviews per Hotel
app.get('/api/analytics/reviews-per-hotel', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        // This query requires a Review model that links to Hotel
        // Example if you have Review model:
        /*
        const reviewsPerHotel = await Review.aggregate([
            {
                $group: {
                    _id: '$hotel', // Group by hotel ID
                    reviewCount: { $sum: 1 },
                    averageRating: { $avg: '$rating' }
                }
            },
            {
                $lookup: {
                    from: 'hotels', // The collection name for Hotel model
                    localField: '_id',
                    foreignField: '_id',
                    as: 'hotelDetails'
                }
            },
            {
                $unwind: '$hotelDetails'
            },
            {
                $project: {
                    _id: 0,
                    hotelId: '$_id',
                    hotelName: '$hotelDetails.name',
                    reviewCount: 1,
                    averageRating: { $round: ['$averageRating', 2] }
                }
            }
        ]);
        */
        // Placeholder data
        const reviewsPerHotel = [
            { hotelId: 'dummy1', hotelName: 'The Oceanfront Resort', reviewCount: 5, averageRating: 4.5 },
            { hotelId: 'dummy2', hotelName: 'Spice Bistro', reviewCount: 3, averageRating: 3.8 },
        ];
        res.json(reviewsPerHotel);
    } catch (error) {
        console.error('Error fetching reviews per hotel analytics:', error);
        res.status(500).json({ message: 'Failed to fetch reviews per hotel analytics', error: error.message });
    }
});

// Recent Reviews
app.get('/api/analytics/recent-reviews', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        // This query requires a Review model that links to User and Hotel
        // Example if you have Review model:
        /*
        const recentReviews = await Review.find()
            .sort({ createdAt: -1 })
            .limit(5)
            .populate('user', 'username') // Populate user details
            .populate('hotel', 'name'); // Populate hotel details
        */
        // Placeholder data
        const recentReviews = [
            { _id: 'r1', comment: 'Great service!', rating: 5, userName: 'Alice', hotel: { name: 'The Oceanfront Resort' }, createdAt: new Date() },
            { _id: 'r2', comment: 'Food was okay.', rating: 3, userName: 'Bob', hotel: { name: 'Spice Bistro' }, createdAt: new Date(Date.now() - 86400000) }, // 1 day ago
        ];
        res.json(recentReviews);
    } catch (error) {
        console.error('Error fetching recent reviews analytics:', error);
        res.status(500).json({ message: 'Failed to fetch recent reviews analytics', error: error.message });
    }
});


// --- Server Start ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access the backend at http://localhost:${PORT}`);
});

// Export models for use in other files (if we modularize later)
export { Hotel, User };
