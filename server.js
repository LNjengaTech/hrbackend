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

// NEW: Review Schema
const reviewSchema = new mongoose.Schema({
    hotel: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Hotel', // References the Hotel model
        required: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // References the User model
        required: true
    },
    userName: { // Store username directly for easier display
        type: String,
        required: true
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5
    },
    comment: {
        type: String,
        trim: true
    }
}, { timestamps: true });

// Add a unique compound index to prevent multiple reviews by the same user for the same hotel
reviewSchema.index({ hotel: 1, user: 1 }, { unique: true });

const Review = mongoose.model('Review', reviewSchema);


// --- JWT Secret ---
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey'; // Use a strong, random key in production!

// --- Middleware for Authentication (JWT Verification) ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) {
        return res.status(401).json({ message: 'Authentication token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, decodedToken) => { // Renamed 'user' to 'decodedToken' for clarity
        if (err) {
            console.error('JWT verification error:', err);
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        // CRITICAL FIX: Assign the nested user object from the decoded token to req.user
        req.user = decodedToken.user;
        console.log("authenticateToken: JWT verified. User payload from token (after fix):", req.user); // Log the corrected user object
        next();
    });
};

// --- Middleware for Admin Authorization ---
const authorizeAdmin = (req, res, next) => {
    // Check if req.user exists and if req.user.isAdmin is true
    console.log("authorizeAdmin: Checking user privileges. req.user:", req.user);
    if (!req.user || !req.user.isAdmin) {
        console.warn("authorizeAdmin: Access denied for user:", req.user ? req.user.email : "No user", "isAdmin:", req.user ? req.user.isAdmin : "N/A");
        return res.status(403).json({ message: 'Access denied: Admin privileges required' });
    }
    console.log("authorizeAdmin: Access granted for user:", req.user.email);
    next();
};

// --- API Routes ---

// Test route
app.get('/', (req, res) => {
    res.send('Rating App Backend is running!');
});

// TEMPORARY: Route to create an admin user for testing (Keep this for now)
app.post('/api/seed-admin', async (req, res) => {
    try {
        const adminEmail = 'admin@example.com';
        let adminUser = await User.findOne({ email: adminEmail });

        if (adminUser) {
            // Update existing user to ensure isAdmin is true, in case it was false
            if (!adminUser.isAdmin) {
                adminUser.isAdmin = true;
                await adminUser.save();
                return res.status(200).json({ message: 'Admin user already exists, isAdmin updated to true.' });
            }
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
        // Also delete all reviews associated with this hotel
        await Review.deleteMany({ hotel: id });
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
            user: { // Ensure this 'user' object is consistently present and includes isAdmin
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.isAdmin
            }
        };

        console.log("Login Route: JWT Payload being signed:", payload);

        jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: '1h' }, // Token expires in 1 hour
            (err, token) => {
                if (err) {
                    console.error("JWT Sign Error:", err);
                    return res.status(500).json({ message: 'Error signing token' });
                }
                res.json({
                    message: 'Logged in successfully!',
                    token, // The actual JWT token string
                    user: { // The user object to be sent to the frontend response body
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        isAdmin: user.isAdmin
                    }
                });
            }
        );

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login', error: error.message });
    }
});

// --- Review Routes ---

// Submit a new review (User protected)
app.post('/api/reviews', authenticateToken, async (req, res) => {
    const { hotel: hotelId, rating, comment } = req.body;
    const userId = req.user.id; // User ID from authenticated token
    const userName = req.user.username; // Username from authenticated token

    if (!hotelId || !rating || !userId || !userName) {
        return res.status(400).json({ message: 'Hotel ID, rating, user ID, and username are required for a review.' });
    }

    try {
        // Check if the user has already reviewed this hotel
        const existingReview = await Review.findOne({ hotel: hotelId, user: userId });
        if (existingReview) {
            return res.status(409).json({ message: 'You have already submitted a review for this hotel.' });
        }

        const newReview = new Review({
            hotel: hotelId,
            user: userId,
            userName: userName, // Store username directly
            rating,
            comment
        });

        await newReview.save();
        res.status(201).json({ message: 'Review submitted successfully!', review: newReview });
    } catch (error) {
        console.error('Error submitting review:', error);
        res.status(500).json({ message: 'Failed to submit review', error: error.message });
    }
});

// Get reviews for a specific hotel (Publicly accessible)
app.get('/api/reviews/hotel/:hotelId', async (req, res) => {
    const { hotelId } = req.params;
    try {
        const reviews = await Review.find({ hotel: hotelId })
            .populate('user', 'username') // Populate user details if needed, though userName is stored directly
            .sort({ createdAt: -1 }); // Latest reviews first
        res.status(200).json(reviews);
    } catch (error) {
        console.error('Error fetching reviews for hotel:', error);
        res.status(500).json({ message: 'Failed to fetch reviews', error: error.message });
    }
});


// --- Analytics Routes (Admin Protected) ---

// Overall Analytics
app.get('/api/analytics/overall', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const totalHotels = await Hotel.countDocuments();
        const totalUsers = await User.countDocuments();
        const totalReviews = await Review.countDocuments(); // Fetch actual count
        const avgRatingResult = await Review.aggregate([
            { $group: { _id: null, averageRating: { $avg: '$rating' } } }
        ]);
        const averageRating = avgRatingResult.length > 0 ? avgRatingResult[0].averageRating.toFixed(2) : 0;

        res.json({ totalHotels, totalUsers, totalReviews, averageRating });
    } catch (error) {
        console.error('Error fetching overall analytics:', error);
        res.status(500).json({ message: 'Failed to fetch overall analytics', error: error.message });
    }
});

// Reviews per Hotel
app.get('/api/analytics/reviews-per-hotel', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
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
                    from: 'hotels', // The collection name for Hotel model (lowercase, plural)
                    localField: '_id',
                    foreignField: '_id',
                    as: 'hotelDetails'
                }
            },
            {
                $unwind: { path: '$hotelDetails', preserveNullAndEmptyArrays: true } // Use unwind with preserveNullAndEmptyArrays
            },
            {
                $project: {
                    _id: 0,
                    hotelId: '$_id',
                    hotelName: '$hotelDetails.name', // Access name from populated hotelDetails
                    reviewCount: 1,
                    averageRating: { $round: ['$averageRating', 2] }
                }
            },
            {
                $sort: { reviewCount: -1 } // Sort by review count descending
            }
        ]);
        res.json(reviewsPerHotel);
    } catch (error) {
        console.error('Error fetching reviews per hotel analytics:', error);
        res.status(500).json({ message: 'Failed to fetch reviews per hotel analytics', error: error.message });
    }
});

// Recent Reviews
app.get('/api/analytics/recent-reviews', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const recentReviews = await Review.find()
            .sort({ createdAt: -1 })
            .limit(5) // Limit to 5 most recent reviews
            .populate('user', 'username') // Populate user details
            .populate('hotel', 'name'); // Populate hotel details

        // Map to include userName directly from the review document, and hotel name from populated data
        const formattedReviews = recentReviews.map(review => ({
            _id: review._id,
            comment: review.comment,
            rating: review.rating,
            userName: review.userName, // Use userName directly from review document
            hotel: {
                name: review.hotel ? review.hotel.name : 'Unknown Hotel' // Handle case where hotel might not be found
            },
            createdAt: review.createdAt
        }));

        res.json(formattedReviews);
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
export { Hotel, User, Review };
