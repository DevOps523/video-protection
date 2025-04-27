// server.js - Complete Node.js proxy server implementation
// Save this as a separate file and host it on a server

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Your secret key - store in environment variables in production
const SECRET_KEY = process.env.SECRET_KEY || 'your-very-secure-secret-key-change-this';

// ===== CONFIGURATION =====
// Update these with your actual domains
const ALLOWED_DOMAINS = [
  'www.popnovahq.xyz',
  'popnovahq.xyz',
  // Add other domains you want to allow
  'localhost:3000' // For testing
];

// Configure your video providers
const providers = {
  listeamed: {
    baseUrl: 'https://listeamed.net/e/',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Referer': 'https://listeamed.net/'
    }
  },
  streamtape: {
    baseUrl: 'https://streamtape.com/e/',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Referer': 'https://streamtape.com/'
    }
  }
  // Add more providers as needed
};

// ===== MIDDLEWARE =====
// Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, etc)
    if (!origin) return callback(null, true);
    
    // Check if the origin is allowed
    if (ALLOWED_DOMAINS.some(domain => origin.includes(domain))) {
      return callback(null, true);
    }
    
    callback(new Error('CORS policy violation'));
  },
  credentials: true
}));

app.use(bodyParser.json());
app.use(cookieParser());
app.use(limiter);

// ===== HELPER FUNCTIONS =====
// Generate secure tokens
function generateToken(videoId, provider, expiryTime) {
  const expiry = Math.floor(Date.now() / 1000) + expiryTime;
  const data = `${videoId}:${provider}:${expiry}`;
  
  // Create HMAC for better security
  const hmac = crypto.createHmac('sha256', SECRET_KEY);
  hmac.update(data);
  const signature = hmac.digest('base64');
  
  return {
    token: Buffer.from(`${data}:${signature}`).toString('base64'),
    expiry: expiry
  };
}

// Verify tokens
function verifyToken(token) {
  try {
    // Decode the token
    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    const [videoId, provider, expiry, signature] = decoded.split(':');
    
    // Check if token has expired
    const currentTime = Math.floor(Date.now() / 1000);
    if (currentTime > parseInt(expiry)) {
      return { valid: false, reason: 'expired' };
    }
    
    // Verify signature
    const data = `${videoId}:${provider}:${expiry}`;
    const hmac = crypto.createHmac('sha256', SECRET_KEY);
    hmac.update(data);
    const expectedSignature = hmac.digest('base64');
    
    if (signature !== expectedSignature) {
      return { valid: false, reason: 'invalid' };
    }
    
    return { 
      valid: true, 
      data: { 
        videoId, 
        provider, 
        expiry 
      } 
    };
  } catch (error) {
    return { valid: false, reason: 'malformed' };
  }
}

// ===== API ENDPOINTS =====
// Token generation endpoint
app.post('/api/get-token', async (req, res) => {
  try {
    const { videoId, provider } = req.body;
    
    // Validate input
    if (!videoId || !provider || !providers[provider]) {
      return res.status(400).json({ error: 'Invalid request parameters' });
    }
    
    // Check referrer header
    const referer = req.headers.referer || '';
    if (!ALLOWED_DOMAINS.some(domain => referer.includes(domain))) {
      return res.status(403).json({ error: 'Unauthorized domain' });
    }
    
    // Generate token with 30 minute expiry
    const { token, expiry } = generateToken(videoId, provider, 30 * 60);
    
    // Return the token
    res.json({
      token,
      expiry,
      provider
    });
  } catch (error) {
    console.error('Error generating token:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Video proxy endpoint
app.get('/api/stream/:token', async (req, res) => {
  try {
    const { token } = req.params;
    
    // Verify token
    const verification = verifyToken(token);
    if (!verification.valid) {
      return res.status(403).json({ error: `Unauthorized: ${verification.reason}` });
    }
    
    const { videoId, provider } = verification.data;
    
    // Check if provider exists
    if (!providers[provider]) {
      return res.status(400).json({ error: 'Invalid provider' });
    }
    
    // Create the actual video URL
    const videoUrl = `${providers[provider].baseUrl}${videoId}`;
    
    // Forward the request to the actual video provider
    const videoResponse = await axios({
      method: 'get',
      url: videoUrl,
      headers: {
        ...providers[provider].headers,
        // Add extra headers as needed
      },
      responseType: 'stream'
    });
    
    // Forward the content type
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    // Add additional security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Replace SAMEORIGIN with Content-Security-Policy
    res.setHeader('Content-Security-Policy', `frame-ancestors 'self' *.xyz www.popnovahq.xyz`);
    
    // Pipe the video stream to the response
    videoResponse.data.pipe(res);
  } catch (error) {
    console.error('Error streaming video:', error);
    res.status(500).json({ error: 'Failed to stream video' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Start the server
app.listen(port, () => {
  console.log(`Video proxy server running on port ${port}`);
});
