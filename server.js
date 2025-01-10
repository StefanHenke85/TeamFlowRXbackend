const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const crypto = require("crypto");
const { OAuth2Client } = require("google-auth-library");
const {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
} = require("@aws-sdk/client-cognito-identity-provider");

const app = express();

// Erweiterte Middleware-Konfiguration
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
  origin: ['http://63.176.154.221:5173', 'http://localhost:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

// AWS Cognito Konfiguration
const cognitoClient = new CognitoIdentityProviderClient({
  region: "eu-central-1",
});

const CLIENT_ID = "6l2kjlrnd6klqiiddo0q5van83";
const CLIENT_SECRET = "1le51u3n3bs27l9856e7e0gnnc1ps3c6q9srl390ilk083gg0eju";

// Secret-Hash Berechnung
function calculateSecretHash(username) {
  return crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(username + CLIENT_ID)
    .digest("base64");
}

// Google OAuth2.0 Konfiguration
const googleClient = new OAuth2Client("804491155832-v3njmknvrilihrf8655vqd0eeikpvugd.apps.googleusercontent.com");

// Google Token Verifizierung
const verifyGoogleToken = async (token) => {
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: "804491155832-v3njmknvrilihrf8655vqd0eeikpvugd.apps.googleusercontent.com",
    });
    return ticket.getPayload();
  } catch (error) {
    throw new Error("Google-Token Verifizierung fehlgeschlagen");
  }
};

// Health Check Route
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK',
    timestamp: new Date(),
    uptime: process.uptime()
  });
});

// Google Login Route
app.post("/google-login", async (req, res) => {
  const { token } = req.body;

  try {
    const googleUser = await verifyGoogleToken(token);
    const { email, sub, name } = googleUser;

    const params = {
      ClientId: CLIENT_ID,
      Username: email,
      UserAttributes: [
        { Name: "email", Value: email },
        { Name: "name", Value: name },
        { Name: "custom:google_id", Value: sub },
      ],
    };

    try {
      const signUpCommand = new SignUpCommand(params);
      await cognitoClient.send(signUpCommand);
    } catch (err) {
      if (!err.message.includes("UsernameExistsException")) {
        throw err;
      }
    }

    const authParams = {
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: CLIENT_ID,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: sub,
      },
    };

    const authCommand = new InitiateAuthCommand(authParams);
    const response = await cognitoClient.send(authCommand);

    res.status(200).json({
      message: "Login erfolgreich",
      token: response.AuthenticationResult.IdToken,
    });
  } catch (error) {
    console.error("Fehler beim Google Login:"),
      console.error("Fehler beim Google Login:", error.message);
      res.status(400).json({ 
        error: "Google Login fehlgeschlagen",
        details: error.message 
      });
    }
  });
  
  // Register Route
  app.post("/register", async (req, res) => {
    const { username, password, email } = req.body;
  
    if (!username || !password || !email) {
      return res.status(400).json({ 
        error: "Bitte alle erforderlichen Felder ausfüllen" 
      });
    }
  
    const secretHash = calculateSecretHash(username);
  
    const params = {
      ClientId: CLIENT_ID,
      Username: username,
      Password: password,
      UserAttributes: [
        {
          Name: "email",
          Value: email,
        },
      ],
      SecretHash: secretHash,
    };
  
    try {
      const command = new SignUpCommand(params);
      await cognitoClient.send(command);
      res.status(200).json({
        message: "Benutzer erfolgreich registriert. Überprüfen Sie Ihre E-Mail für den Verifizierungscode.",
        username: username
      });
    } catch (error) {
      console.error("Registrierungsfehler:", error);
      res.status(400).json({ 
        error: "Registrierung fehlgeschlagen",
        details: error.message 
      });
    }
  });
  
  // Verify Route
  app.post("/verify", async (req, res) => {
    const { username, code } = req.body;
  
    if (!username || !code) {
      return res.status(400).json({ 
        error: "Benutzername und Verifizierungscode erforderlich" 
      });
    }
  
    const secretHash = calculateSecretHash(username);
  
    const params = {
      ClientId: CLIENT_ID,
      Username: username,
      ConfirmationCode: code,
      SecretHash: secretHash,
    };
  
    try {
      const command = new ConfirmSignUpCommand(params);
      await cognitoClient.send(command);
      res.status(200).json({ 
        message: "Verifizierung erfolgreich!",
        username: username
      });
    } catch (error) {
      console.error("Verifizierungsfehler:", error);
      res.status(400).json({ 
        error: "Verifizierung fehlgeschlagen",
        details: error.message 
      });
    }
  });
  
  // Login Route
  app.post("/login", async (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.status(400).json({ 
        error: "Benutzername und Passwort erforderlich" 
      });
    }
  
    const secretHash = calculateSecretHash(username);
  
    const params = {
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: CLIENT_ID,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
        SECRET_HASH: secretHash,
      },
    };
  
    try {
      const command = new InitiateAuthCommand(params);
      const response = await cognitoClient.send(command);
      res.status(200).json({
        message: "Login erfolgreich",
        token: response.AuthenticationResult.IdToken,
        username: username
      });
    } catch (error) {
      console.error("Login-Fehler:", error);
      res.status(400).json({ 
        error: "Login fehlgeschlagen",
        details: error.message 
      });
    }
  });
  
 // Ein einzelner Global Error Handler
app.use((err, req, res, next) => {
  console.error('Unerwarteter Fehler:', err.stack);
  res.status(500).json({
    error: 'Ein interner Serverfehler ist aufgetreten',
    message: err.message,
    timestamp: new Date().toISOString()
  });
});

// 404 Handler für nicht gefundene Routen
app.use((req, res) => {
  res.status(404).json({
    error: 'Route nicht gefunden',
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// Server starten und in Variable speichern für Graceful Shutdown
const PORT = 5173;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server läuft auf http://63.176.154.221:${PORT}`);
  console.log('Verfügbare Endpunkte:');
  console.log(`- POST http://63.176.154.221:${PORT}/register`);
  console.log(`- POST http://63.176.154.221:${PORT}/verify`);
  console.log(`- POST http://63.176.154.221:${PORT}/login`);
  console.log(`- POST http://63.176.154.221:${PORT}/google-login`);
  console.log(`- GET  http://63.176.154.221:${PORT}/health`);
  console.log('Drücken Sie STRG+C zum Beenden');
});

// Graceful Shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM Signal empfangen. Server wird beendet...');
  server.close(() => {
    console.log('Server erfolgreich beendet');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT Signal empfangen. Server wird beendet...');
  server.close(() => {
    console.log('Server erfolgreich beendet');
    process.exit(0);
  });
});

// Unhandled Rejection Handler
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unbehandelte Promise Rejection:', reason);
  // Anwendung nicht beenden, aber den Fehler loggen
});

// Uncaught Exception Handler
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // In Produktionsumgebung sollten Sie hier einen Neustart des Servers in Betracht ziehen
});
