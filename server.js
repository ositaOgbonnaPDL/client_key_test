const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;

// Sample valid client keys (in a real application, these would be stored securely)
const validClientKeys = [
    'client_key_123',
    'client_key_456',
    'test_key_789'
];

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Middleware to log requests
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Endpoint to validate client key
app.post('/validate-key', (req, res) => {
    const { clientKey } = req.body;

    // Check if client key is provided
    if (!clientKey) {
        return res.status(400).json({
            success: false,
            message: 'Client key is required'
        });
    }

    // Validate the client key
    const isValidKey = validClientKeys.includes(clientKey);

    // Return appropriate response
    if (isValidKey) {
        return res.status(200).json({
            success: true,
            message: 'Valid client key',
            keyDetails: {
                validated: true,
                validatedAt: new Date().toISOString()
            }
        });
    } else {
        return res.status(401).json({
            success: false,
            message: 'Invalid client key'
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Key validation server running on port ${port}`);
});