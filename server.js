const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs").promises;

const app = express();
app.use(
  cors({
    origin: "*", // Be more specific in production
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json()); // For parsing application/json

// Update the MongoDB connection with better error handling
mongoose
  .connect("mongodb://localhost:27017/bloodDonors", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB successfully");
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error);
    process.exit(1); // Exit if MongoDB connection fails
  });

// Define your API key and JWT secret directly in the code
const MAPBOX_API_KEY =
  "pk.eyJ1IjoicHJhaml0ayIsImEiOiJjbTJkZ3dnbnQwZ2V6MmtzYjJ0OHB1MXJlIn0.wDuuekeM9f2DONO7d1kylw";
const JWT_SECRET = "your_jwt_secret";

// Define the donor schema
const donorSchema = new mongoose.Schema({
  name: String,
  bloodGroup: String,
  address: String,
  contact: String,
  email: String,
  latitude: Number,
  longitude: Number,
});
const Donor = mongoose.model("Donor", donorSchema);

// Define the blood bank schema
const bloodBankSchema = new mongoose.Schema({
  name: String,
  address: String,
  contact: String,
  latitude: Number,
  longitude: Number,
});
const BloodBank = mongoose.model("BloodBank", bloodBankSchema);

// Define the user schema
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
});
const User = mongoose.model("User", userSchema);

// Define the blood request schema
const bloodRequestSchema = new mongoose.Schema({
  donorId: { type: mongoose.Schema.Types.ObjectId, ref: "Donor" },
  requesterId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  requiredUnits: Number,
  urgency: String,
  message: String,
  status: { type: String, default: "pending" }, // pending, accepted, rejected
  createdAt: { type: Date, default: Date.now },
});
const BloodRequest = mongoose.model("BloodRequest", bloodRequestSchema);

// Configure multer for file upload
const storage = multer.diskStorage({
  destination: "./uploads/",
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

const upload = multer(); // Simplified multer config

// Helper function to geocode an address using Mapbox
async function geocodeAddress(address, apiKey) {
  const url = `https://api.mapbox.com/geocoding/v5/mapbox.places/${encodeURIComponent(
    address
  )}.json?access_token=${apiKey}`;
  try {
    const response = await axios.get(url);
    if (response.data.features && response.data.features.length > 0) {
      const location = response.data.features[0].geometry.coordinates;
      console.log("Geocoded coordinates:", {
        lng: location[0],
        lat: location[1],
      });
      return { lat: location[1], lng: location[0] };
    } else {
      throw new Error("No location found for this address");
    }
  } catch (error) {
    console.error("Geocoding error:", error);
    throw new Error("Failed to geocode address: " + error.message);
  }
}

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    console.log("No token provided");
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log("Token verification failed:", err.message);
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    console.log("Token verified successfully for user:", user);
    req.user = user;
    next();
  });
};

// Endpoint to fetch user profile
app.get("/user-profile", authenticateToken, async (req, res) => {
  try {
    // Log the user ID from the token for debugging
    console.log("User ID from token:", req.user.userId);

    const user = await User.findById(req.user.userId);
    if (!user) {
      console.log("User not found in database");
      return res.status(404).json({ error: "User not found" });
    }

    // Log the found user (without password)
    console.log("Found user:", {
      id: user._id,
      username: user.username,
      email: user.email,
    });

    res.json({
      email: user.email,
      username: user.username,
    });
  } catch (error) {
    console.error("Error in user-profile endpoint:", error);
    res.status(500).json({
      error: "Error fetching user profile",
      details: error.message,
    });
  }
});

function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Radius of the earth in km
  const dLat = deg2rad(lat2 - lat1);
  const dLon = deg2rad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(deg2rad(lat1)) *
      Math.cos(deg2rad(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c; // Distance in km
}

function deg2rad(deg) {
  return deg * (Math.PI / 180);
}

// API endpoint to register a donor
app.post("/donors", authenticateToken, async (req, res) => {
  try {
    console.log("Received donor registration request:", req.body);
    const { bloodType, address, contact } = req.body;

    if (!bloodType || !address || !contact) {
      return res.status(400).json({
        error: "Missing required fields",
        message: "Blood type, address, and contact are required",
      });
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if user is already registered as a donor
    const existingDonor = await Donor.findOne({ email: user.email });
    if (existingDonor) {
      return res.status(400).json({
        error: "Already registered",
        message: "You are already registered as a donor",
      });
    }

    // Geocode the address with better error handling
    let coordinates;
    try {
      coordinates = await geocodeAddress(address, MAPBOX_API_KEY);
      console.log("Geocoded coordinates for donor:", coordinates);
    } catch (error) {
      return res.status(400).json({
        error: "Failed to geocode address",
        message: error.message,
      });
    }

    // Create and save donor with verified coordinates
    const newDonor = new Donor({
      name: user.username,
      bloodGroup: bloodType,
      address,
      contact,
      email: user.email,
      latitude: coordinates.lat,
      longitude: coordinates.lng,
    });

    await newDonor.save();
    console.log("Donor saved successfully:", newDonor);

    res.status(201).json({
      message: "Donor registered successfully",
      donor: newDonor,
    });
  } catch (error) {
    console.error("Error during donor registration:", error);
    res.status(500).json({
      error: "Failed to register donor",
      message: error.message,
    });
  }
});

// API endpoint to retrieve all donors
app.get("/donors", async (req, res) => {
  try {
    const donors = await Donor.find({});
    res.send(donors);
  } catch (error) {
    console.error("Error fetching donors:", error.message);
    res.status(500).send({ error: error.message });
  }
});

// User signup endpoint
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Hash password and create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ error: "Error registering user: " + error.message });
  }
});

// User login endpoint
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      token,
      username: user.username,
      message: "Login successful",
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Error during login: " + error.message });
  }
});

// API endpoint to register a blood bank
app.post("/bloodbanks", async (req, res) => {
  const { name, address, contact, latitude, longitude } = req.body;

  if (!name || !address || !contact || !latitude || !longitude) {
    return res.status(400).send({ error: "All fields are required" });
  }

  try {
    const newBloodBank = new BloodBank({
      name,
      address,
      contact,
      latitude,
      longitude,
    });

    await newBloodBank.save();
    res.status(201).send(newBloodBank);
  } catch (error) {
    console.error("Error during blood bank registration:", error.message);
    res.status(500).send({ error: error.message });
  }
});

// API endpoint to retrieve all blood banks
app.get("/bloodbanks", async (req, res) => {
  try {
    const bloodBanks = await BloodBank.find({});
    res.send(bloodBanks);
  } catch (error) {
    console.error("Error fetching blood banks:", error.message);
    res.status(500).send({ error: error.message });
  }
});

// API endpoint to create a blood request
app.post("/blood-request", authenticateToken, async (req, res) => {
  try {
    const { donorId, requiredUnits, urgency, message } = req.body;

    // Validate required fields
    if (!donorId || !requiredUnits || !urgency || !message) {
      return res.status(400).json({
        error: "Missing required fields",
      });
    }

    // Find the donor
    const donor = await Donor.findById(donorId);
    if (!donor) {
      return res.status(404).json({ error: "Donor not found" });
    }

    // Create new request
    const newRequest = new BloodRequest({
      donorId,
      requesterId: req.user.userId,
      requiredUnits,
      urgency,
      message,
      status: "pending",
    });

    await newRequest.save();

    res.status(201).json({
      message: "Blood request created successfully",
      request: newRequest,
    });
  } catch (error) {
    console.error("Error creating blood request:", error);
    res.status(500).json({
      error: "Failed to create blood request",
      message: error.message,
    });
  }
});

// API endpoint to get blood requests for a donor
app.get("/donor-requests", authenticateToken, async (req, res) => {
  try {
    // First find if the logged-in user is a donor
    const donor = await Donor.findOne({ email: req.user.email });
    if (!donor) {
      return res.status(404).json({ error: "Donor not found" });
    }

    // Find all requests where donorId matches the donor's ID
    const requests = await BloodRequest.find({ donorId: donor._id })
      .populate("requesterId", "username email") // Include requester details
      .sort({ createdAt: -1 }); // Sort by newest first

    res.json(requests);
  } catch (error) {
    console.error("Error fetching blood requests:", error);
    res.status(500).json({ error: error.message });
  }
});

// Add an endpoint to update request status
app.put(
  "/blood-request/:requestId/status",
  authenticateToken,
  async (req, res) => {
    try {
      const { status } = req.body;
      const request = await BloodRequest.findByIdAndUpdate(
        req.params.requestId,
        { status },
        { new: true }
      );
      res.json(request);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get("/nearest-bloodbank/:donorId", authenticateToken, async (req, res) => {
  try {
    const donor = await Donor.findById(req.params.donorId);
    if (!donor) {
      return res.status(404).json({ error: "Donor not found" });
    }

    const bloodBanks = await BloodBank.find({});
    if (!bloodBanks.length) {
      return res.status(404).json({ error: "No blood banks found" });
    }

    // Find nearest blood bank
    let nearestBank = bloodBanks[0];
    let shortestDistance = calculateDistance(
      donor.latitude,
      donor.longitude,
      bloodBanks[0].latitude,
      bloodBanks[0].longitude
    );

    for (const bank of bloodBanks) {
      const distance = calculateDistance(
        donor.latitude,
        donor.longitude,
        bank.latitude,
        bank.longitude
      );
      if (distance < shortestDistance) {
        shortestDistance = distance;
        nearestBank = bank;
      }
    }
    res.json(nearestBank);
  } catch (error) {
    console.error("Error finding nearest blood bank:", error);
    res.status(500).json({ error: error.message });
  }
});

// Add this new endpoint in your server.js
app.get("/check-donor", authenticateToken, async (req, res) => {
  try {
    // Find donor by email (since we stored email during registration)
    const donor = await Donor.findOne({ email: req.user.email });

    // Send back whether the user is a donor or not
    res.json({ isDonor: !!donor });
  } catch (error) {
    console.error("Error checking donor status:", error);
    res.status(500).json({ error: error.message });
  }
});

// Update the createUploadsDirectory function
const createUploadsDirectory = async () => {
  const uploadPath = "./uploads";
  try {
    await fs.access(uploadPath);
  } catch {
    try {
      await fs.mkdir(uploadPath, { recursive: true });
      console.log("Created uploads directory");
    } catch (error) {
      console.error("Error creating uploads directory:", error);
      throw error;
    }
  }
};

// Update the port number to be consistent
const PORT = process.env.PORT || 3001;

// Wrap server initialization in an async function
async function startServer() {
  try {
    // Create uploads directory
    await createUploadsDirectory();

    // Start the server
    app
      .listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
      })
      .on("error", (err) => {
        if (err.code === "EADDRINUSE") {
          console.error(`Port ${PORT} is busy. Please try a different port`);
          process.exit(1);
        } else {
          console.error("Server error:", err);
          process.exit(1);
        }
      });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

// Call the async function to start the server
startServer().catch(console.error);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: "Something went wrong!",
    message: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

// Update the seeker requests endpoint
app.get("/seeker-requests", authenticateToken, async (req, res) => {
  try {
    // Changed from req.user.id to req.user.userId
    const requests = await BloodRequest.find({ requesterId: req.user.userId })
      .populate("donorId", "name email contact") // Specify which donor fields to populate
      .sort({ createdAt: -1 });

    console.log("Found requests:", requests); // For debugging
    res.json(requests);
  } catch (error) {
    console.error("Error fetching seeker requests:", error);
    res.status(500).json({
      error: "Failed to fetch requests",
      details: error.message,
    });
  }
});
