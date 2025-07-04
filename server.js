// server.js (main backend file)

// Import necessary packages
import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors'; // Import cors
import bcrypt from 'bcryptjs'; // For password hashing
import jwt from 'jsonwebtoken'; // For JSON Web Tokens
import twilio from 'twilio'; // Twilio module

// Load environment variables from .env file
dotenv.config();

// Initialize Express app
const app = express();

// --- CORS Configuration ---
// In production, replace '*' with your actual frontend URL (e.g., 'https://your-frontend-app.vercel.app')
app.use(cors({
    origin: 'https://hotel-review-self.vercel.app', // Allows all origins for now. IMPORTANT: Change this in production!
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Middleware
app.use(express.json()); // For parsing application/json

// --- Database Connection ---
const MONGODB_URI = process.env.MONGODB_URI; // No fallback here, must be in Render env vars

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

// Review Schema
const reviewSchema = new mongoose.Schema({
    hotel: { // Reference to the Hotel model
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Hotel',
        required: true
    },
    user: { // Reference to the User model
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
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
        trim: true,
        maxlength: 500 // Optional: limit comment length
    }
}, { timestamps: true });

const Review = mongoose.model('Review', reviewSchema);


// --- JWT Secret ---
const JWT_SECRET = process.env.JWT_SECRET; // No fallback here, must be in Render env vars

// --- Twilio Configuration (for WhatsApp) ---
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;
const ADMIN_WHATSAPP_NUMBER = process.env.ADMIN_WHATSAPP_NUMBER;

// Initialize Twilio client (only if credentials are provided)
let twilioClient;
if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
    twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
} else {
    console.warn('Twilio client not initialized: TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN missing.');
}


// Function to send WhatsApp notification (REAL IMPLEMENTATION)
const sendWhatsAppNotification = async (messageBody) => {
    if (!twilioClient || !TWILIO_PHONE_NUMBER || !ADMIN_WHATSAPP_NUMBER) {
        console.error('Twilio client not fully configured or initialized. Skipping real WhatsApp notification.');
        console.log('\n--- FALLBACK TO SIMULATED WHATSAPP NOTIFICATION ---');
        console.log(`To: ${ADMIN_WHATSAPP_NUMBER || 'Admin WhatsApp Number'}`);
        console.log(`Message: ${messageBody}`);
        console.log('---------------------------------------------------\n');
        return;
    }

    try {
        await twilioClient.messages.create({
            from: TWILIO_PHONE_NUMBER, // Your Twilio WhatsApp number
            to: ADMIN_WHATSAPP_NUMBER, // Admin's WhatsApp number
            body: messageBody
        });
        console.log('WhatsApp notification sent successfully!');
    } catch (error) {
        console.error('Failed to send WhatsApp notification via Twilio:', error);
        // Fallback to console log if real sending fails
        console.log('\n--- WHATSAPP NOTIFICATION FAILED (SEE ERROR ABOVE), FALLING BACK TO CONSOLE LOG ---');
        console.log(`To: ${ADMIN_WHATSAPP_NUMBER}`);
        console.log(`Message: ${messageBody}`);
        console.log('----------------------------------------------------------------------------------\n');
    }
};


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
        req.user = user; // Attach user payload to request (contains id, username, email, isAdmin)
        next();
    });
};

// Middleware for Admin Authorization
const authorizeAdmin = (req, res, next) => {
    if (!req.user || !req.user.user.isAdmin) {
        return res.status(403).json({ message: 'Access denied: Admin privileges required' });
    }
    next();
};

// --- API Routes ---

// Test route
app.get('/', (req, res) => {
    res.send('Rating App Backend is running!');
});

// Route to get all hotels
app.get('/api/hotels', async (req, res) => {
    try {
        const hotels = await Hotel.find({});
        res.status(200).json(hotels);
    } catch (error) {
        console.error('Error fetching hotels:', error);
        res.status(500).json({ message: 'Failed to fetch hotels', error: error.message });
    }
});

// Route to get a single hotel by ID
app.get('/api/hotels/:id', async (req, res) => {
    try {
        const hotel = await Hotel.findById(req.params.id);
        if (!hotel) {
            return res.status(404).json({ message: 'Hotel not found' });
        }
        res.status(200).json(hotel);
    } catch (error) {
        console.error('Error fetching single hotel:', error);
        res.status(500).json({ message: 'Failed to fetch hotel', error: error.message });
    }
});

// --- Hotel Management Routes (Admin Only) ---

// Add a new hotel (Admin Only)
app.post('/api/hotels', authenticateToken, authorizeAdmin, async (req, res) => {
    const { name, location, description, imageUrl } = req.body;

    if (!name || !location) {
        return res.status(400).json({ message: 'Hotel name and location are required.' });
    }

    try {
        const newHotel = new Hotel({
            name,
            location,
            description,
            imageUrl
        });
        await newHotel.save();
        res.status(201).json({ message: 'Hotel added successfully!', hotel: newHotel });
    } catch (error) {
        if (error.code === 11000) { // Duplicate key error (for unique name)
            return res.status(400).json({ message: 'A hotel with this name already exists.' });
        }
        console.error('Error adding hotel:', error);
        res.status(500).json({ message: 'Failed to add hotel', error: error.message });
    }
});

// Update an existing hotel (Admin Only)
app.put('/api/hotels/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, location, description, imageUrl } = req.body;

    if (!name || !location) {
        return res.status(400).json({ message: 'Hotel name and location are required.' });
    }

    try {
        const updatedHotel = await Hotel.findByIdAndUpdate(
            id,
            { name, location, description, imageUrl },
            { new: true, runValidators: true } // Return the updated document and run schema validators
        );

        if (!updatedHotel) {
            return res.status(404).json({ message: 'Hotel not found.' });
        }
        res.status(200).json({ message: 'Hotel updated successfully!', hotel: updatedHotel });
    } catch (error) {
        if (error.code === 11000) { // Duplicate key error (for unique name)
            return res.status(400).json({ message: 'A hotel with this name already exists.' });
        }
        console.error('Error updating hotel:', error);
        res.status(500).json({ message: 'Failed to update hotel', error: error.message });
    }
});

// Delete a hotel (Admin Only)
app.delete('/api/hotels/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        // Optional: Delete all reviews associated with this hotel first
        await Review.deleteMany({ hotel: id });
        console.log(`Deleted reviews for hotel ID: ${id}`);

        const deletedHotel = await Hotel.findByIdAndDelete(id);

        if (!deletedHotel) {
            return res.status(404).json({ message: 'Hotel not found.' });
        }
        res.status(200).json({ message: 'Hotel and associated reviews deleted successfully!' });
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
            user: {
                id: user.id, // Mongoose virtual 'id' for _id
                username: user.username,
                email: user.email,
                isAdmin: user.isAdmin
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
                    token,
                    user: {
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

// Example of a protected route (can be accessed only by authenticated users)
app.get('/api/auth/protected', authenticateToken, (req, res) => {
    res.json({
        message: `Welcome, ${req.user.username}! You accessed a protected route.`,
        user: req.user
    });
});

// --- Review Routes ---

// Submit a new review (PROTECTED ROUTE)
app.post('/api/reviews', authenticateToken, async (req, res) => {
    const { hotelId, rating, comment } = req.body;
    const userId = req.user.user.id; // User ID from JWT payload
    const userName = req.user.user.username; // Username from JWT payload

    if (!hotelId || !rating || !comment) {
        return res.status(400).json({ message: 'Please provide hotel ID, rating, and comment' });
    }

    if (rating < 1 || rating > 5) {
        return res.status(400).json({ message: 'Rating must be between 1 and 5' });
    }

    try {
        // Check if the hotel exists
        const hotelExists = await Hotel.findById(hotelId);
        if (!hotelExists) {
            return res.status(404).json({ message: 'Hotel not found' });
        }

        // Check if the user has already reviewed this hotel (optional, but good practice)
        const existingReview = await Review.findOne({ hotel: hotelId, user: userId });
        if (existingReview) {
            return res.status(400).json({ message: 'You have already reviewed this hotel.' });
        }

        const newReview = new Review({
            hotel: hotelId,
            user: userId,
            userName, // Store username directly
            rating,
            comment
        });

        await newReview.save();

        // --- WhatsApp Notification Trigger ---
        const notificationMessage =
            `New Review Submitted!\n` +
            `Hotel: ${hotelExists.name}\n` +
            `Reviewed by: ${userName}\n` +
            `Rating: ${rating} stars\n` +
            `Comment: "${comment}"`;

        sendWhatsAppNotification(notificationMessage); // Call the actual Twilio function

        res.status(201).json({ message: 'Review submitted successfully!', review: newReview });

    } catch (error) {
        console.error('Error submitting review:', error);
        res.status(500).json({ message: 'Server error during review submission', error: error.message });
    }
});

// Get all reviews for a specific hotel
app.get('/api/reviews/:hotelId', async (req, res) => {
    try {
        const reviews = await Review.find({ hotel: req.params.hotelId }).sort({ createdAt: -1 }); // Sort by newest first
        res.status(200).json(reviews);
    } catch (error) {
        console.error('Error fetching reviews:', error);
        res.status(500).json({ message: 'Server error fetching reviews', error: error.message });
    }
});

// --- Analytics Routes (PROTECTED BY ADMIN AUTHORIZATION) ---

// Get overall analytics data
app.get('/api/analytics/overall', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const totalHotels = await Hotel.countDocuments();
        const totalUsers = await User.countDocuments();
        const totalReviews = await Review.countDocuments();

        // Calculate average rating
        const avgRatingResult = await Review.aggregate([
            {
                $group: {
                    _id: null,
                    averageRating: { $avg: "$rating" }
                }
            }
        ]);
        const averageRating = avgRatingResult.length > 0 ? parseFloat(avgRatingResult[0].averageRating.toFixed(2)) : 0;

        res.status(200).json({
            totalHotels,
            totalUsers,
            totalReviews,
            averageRating
        });
    } catch (error) {
        console.error('Error fetching overall analytics:', error);
        res.status(500).json({ message: 'Failed to fetch overall analytics', error: error.message });
    }
});

// Get review counts per hotel
app.get('/api/analytics/reviews-per-hotel', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const reviewsPerHotel = await Review.aggregate([
            {
                $group: {
                    _id: "$hotel", // Group by hotel ID
                    count: { $sum: 1 },
                    averageRating: { $avg: "$rating" }
                }
            },
            {
                $lookup: { // Join with Hotel collection to get hotel name
                    from: "hotels", // The name of the collection in MongoDB (usually lowercase plural of model name)
                    localField: "_id",
                    foreignField: "_id",
                    as: "hotelDetails"
                }
            },
            {
                $unwind: "$hotelDetails" // Deconstructs the array produced by $lookup
            },
            {
                $project: { // Project only necessary fields
                    _id: 0,
                    hotelId: "$_id",
                    hotelName: "$hotelDetails.name",
                    reviewCount: "$count",
                    averageRating: { $round: ["$averageRating", 2] } // Round to 2 decimal places
                }
            },
            {
                $sort: { reviewCount: -1 } // Sort by review count descending
            }
        ]);

        res.status(200).json(reviewsPerHotel);
    } catch (error) {
        console.error('Error fetching reviews per hotel analytics:', error);
        res.status(500).json({ message: 'Failed to fetch reviews per hotel analytics', error: error.message });
    }
});

// Get recent reviews (e.g., last 10)
app.get('/api/analytics/recent-reviews', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const recentReviews = await Review.find({})
            .sort({ createdAt: -1 }) // Sort by newest first
            .limit(10) // Limit to last 10 reviews
            .populate('hotel', 'name') // Populate hotel name
            .select('userName rating comment createdAt hotel'); // Select specific fields

        res.status(200).json(recentReviews);
    } catch (error) {
        console.error('Error fetching recent reviews:', error);
        res.status(500).json({ message: 'Failed to fetch recent reviews', error: error.message });
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
