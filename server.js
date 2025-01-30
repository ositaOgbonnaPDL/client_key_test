const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const app = express();
const port = 3000;

// Sample valid client keys (in a real application, these would be stored securely)
const validClientKeys = ["client_key_123", "client_key_456", "test_key_789"];

// Create the dav_responses directory if it doesn't exist
const responsesDir = path.join(__dirname, "dav_responses");
if (!fs.existsSync(responsesDir)) {
  fs.mkdirSync(responsesDir);
}

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Middleware to parse text bodies
app.use(bodyParser.text({ type: "text/*" }));

// Middleware to log requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Endpoint to validate client key
app.post("/validate-key", (req, res) => {
  try {
    // Get headers
    const authHeader = req.headers["authorization"];
    const environment = req.headers["x-environment"];
    const nonce = req.headers["x-nonce"];

    // Validate required headers
    if (!authHeader || !environment || !nonce) {
      return res.status(400).json({
        valid: false,
        message: "Missing required headers",
      });
    }

    // Validate Authorization header format
    if (!authHeader.startsWith("Bearer ")) {
      return res.status(400).json({
        valid: false,
        message: "Invalid Authorization header format",
      });
    }

    // Extract client key from Authorization header
    const clientKey = authHeader.split(" ")[1];

    // Validate client key
    if (!validClientKeys.includes(clientKey)) {
      return res.status(401).json({
        valid: false,
        message: "Invalid client key",
      });
    }

    // Validate request body
    if (!req.body.nonce || !req.body.environment) {
      return res.status(400).json({
        valid: false,
        message: "Missing required body parameters",
      });
    }

    // Verify nonce matches
    if (req.body.nonce !== nonce) {
      return res.status(400).json({
        valid: false,
        message: "Nonce mismatch",
      });
    }

    // Verify environment matches
    if (req.body.environment !== environment) {
      return res.status(400).json({
        valid: false,
        message: "Environment mismatch",
      });
    }

    // All validations passed
    return res.status(200).json({
      valid: true,
      environment: environment,
      nonce: nonce,
      validatedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Validation error:", error);
    return res.status(500).json({
      valid: false,
      message: "Internal server error",
    });
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    timestamp: new Date().toISOString(),
  });
});

// Webhook route to receive and save responses
app.post("/webhook", (req, res) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const fileName = `response-${timestamp}.txt`;
  const filePath = path.join(responsesDir, fileName);

  try {
    let responseData;
    if (req.is("application/json")) {
      responseData = JSON.stringify(req.body, null, 2);
    } else {
      responseData = req.body;
    }

    fs.writeFileSync(filePath, responseData);
    console.log(`Webhook response saved to: ${filePath}`);
    res.status(200).json({ message: "Response received and saved." });
  } catch (error) {
    console.error("Error saving webhook response:", error);
    res.status(500).json({ error: "Failed to save response." });
  }
});

// Endpoint to handle verification status updates
app.post("/update", (req, res) => {
  try {
    // Get headers
    const apiKey = req.headers["x-API_KEY"];

    if (!apiKey) {
      return res.status(400).json({
        success: false,
        message: "Missing client key",
      });
    }
    // Validate client key
    if (!validClientKeys.includes(apiKey)) {
      return res.status(401).json({
        success: false,
        message: "Invalid client key",
      });
    }

    // Save the verification update to a file
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const fileName = `verification-update-${timestamp}.json`;
    const filePath = path.join(responsesDir, fileName);

    const updateData = {
      ...req.body,
      timestamp: new Date().toISOString(),
      apiKey: apikey,
    };

    fs.writeFileSync(filePath, JSON.stringify(updateData, null, 2));
    console.log(`Verification update saved to: ${filePath}`);

    // Return success response
    return res.status(200).json({
      success: true,
      message: "Verification status updated successfully",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Update verification error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: "Something went wrong!",
    message: err.message,
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Key validation server running on port ${port}`);
});
