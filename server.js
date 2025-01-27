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
  const { clientKey } = req.body;
  const authorizationHeader = req.headers["authorization"];
  const environmentHeader = req.headers["x-environment"];
  const nonceHeader = req.headers["x-nonce"];
  const timestampHeader = req.headers["x-timestamp"];

  // Check if the necessary headers are present
  if (!authorizationHeader) {
    return res.status(400).json({
      success: false,
      message: "Authorization header is required",
    });
  }

  if (!environmentHeader) {
    return res.status(400).json({
      success: false,
      message: "X-Environment header is required",
    });
  }

  if (!nonceHeader) {
    return res.status(400).json({
      success: false,
      message: "X-Nonce header is required",
    });
  }

  if (!timestampHeader) {
    return res.status(400).json({
      success: false,
      message: "X-Timestamp header is required",
    });
  }

  // Check if the 'Authorization' header contains a valid Bearer token
  if (!authorizationHeader.startsWith("Bearer ")) {
    return res.status(400).json({
      success: false,
      message: "Authorization header must be in the form 'Bearer <token>'",
    });
  }

  const clientKeyFromHeader = authorizationHeader.split(" ")[1];

  // Check if the 'clientKey' in the body matches the token in the Authorization header
  if (validClientKeys.includes(clientKeyFromHeader)) {
    return res.status(403).json({
      success: false,
      message: "Invalid client key",
    });
  }

  // Validate other body data (e.g., nonce, environment)
  if (!req.body.nonce || !req.body.environment) {
    return res.status(400).json({
      success: false,
      message: "Nonce and environment are required in the request body",
    });
  }

  // Optional: Validate timestamp (e.g., check if it's within an acceptable range)
  const requestTime = new Date(timestampHeader);
  const currentTime = new Date();
  const timeDiff = Math.abs(currentTime - requestTime);
  if (timeDiff > 5 * 60 * 1000) {
    // Example: 5-minute window
    return res.status(400).json({
      success: false,
      message: "Request timestamp is too old",
    });
  }

  // If all checks pass, respond with success
  return res.status(200).json({
    success: true,
    message: "Validation successful",
  });
});
// app.post("/validate-key", (req, res) => {
//   const { clientKey } = req.body;

//   // Check if client key is provided
//   if (!clientKey) {
//     return res.status(400).json({
//       success: false,
//       message: "Client key is required",
//     });
//   }

//   // Validate the client key
//   const isValidKey = validClientKeys.includes(clientKey);

//   // Return appropriate response
//   if (isValidKey) {
//     return res.status(200).json({
//       success: true,
//       message: "Valid client key",
//       keyDetails: {
//         validated: true,
//         validatedAt: new Date().toISOString(),
//       },
//     });
//   } else {
//     return res.status(401).json({
//       success: false,
//       message: "Invalid client key",
//     });
//   }
// });

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    timestamp: new Date().toISOString(),
  });
});

// Webhook route to receive and save responses
app.post("/webhook", (req, res) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-"); // Replace colons and dots for filename
  const fileName = `response-${timestamp}.txt`;
  const filePath = path.join(responsesDir, fileName);

  try {
    let responseData;
    if (req.is("application/json")) {
      responseData = JSON.stringify(req.body, null, 2); // Format JSON for readability
      fs.writeFileSync(filePath, responseData);
    } else {
      responseData = req.body;
      fs.writeFileSync(filePath, responseData);
    }

    console.log(`Webhook response saved to: ${filePath}`);
    res.status(200).send({ message: "Response received and saved." });
  } catch (error) {
    console.error("Error saving webhook response:", error);
    res.status(500).send({ error: "Failed to save response." });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Key validation server running on port ${port}`);
});
