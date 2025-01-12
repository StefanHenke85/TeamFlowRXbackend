require("dotenv").config(); // Für Umgebungsvariablen
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
} = require("@aws-sdk/client-cognito-identity-provider");

const app = express();

// Middleware-Konfiguration
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb" }));
app.use(
  cors({
    origin: ["http://63.176.154.221:5173", "http://localhost:5173"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  })
);

// AWS Cognito Konfiguration
const cognitoClient = new CognitoIdentityProviderClient({
  region: "eu-central-1",
});

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

// Secret-Hash Berechnung
function calculateSecretHash(username) {
  return crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(username + CLIENT_ID)
    .digest("base64");
}

// Google OAuth2.0 Konfiguration
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Google Token Verifizierung
const verifyGoogleToken = async (token) => {
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    return ticket.getPayload();
  } catch (error) {
    throw new Error("Google-Token Verifizierung fehlgeschlagen");
  }
};

// JWT-Generierung
const generateJWT = (user) => {
  return jwt.sign(
    { username: user.Username, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
};

// Middleware zur JWT-Authentifizierung
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ error: "Token ungültig" });
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ error: "Auth-Token erforderlich" });
  }
};

// Health Check Route
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    timestamp: new Date(),
    uptime: process.uptime(),
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

    const token = generateJWT({ Username: email, email });
    res.status(200).json({
      message: "Login erfolgreich",
      token,
    });
  } catch (error) {
    console.error("Fehler beim Google Login:", error.message);
    res.status(400).json({
      error: "Google Login fehlgeschlagen",
      details: error.message,
    });
  }
});

// Register Route
app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: "Bitte alle Felder ausfüllen" });
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
      message:
        "Benutzer erfolgreich registriert. Überprüfen Sie Ihre E-Mail für den Verifizierungscode.",
    });
  } catch (error) {
    console.error("Registrierungsfehler:", error);
    res.status(400).json({ error: "Registrierung fehlgeschlagen" });
  }
});

// Verify Route
app.post("/verify", async (req, res) => {
  const { username, code } = req.body;

  if (!username || !code) {
    return res.status(400).json({
      error: "Benutzername und Verifizierungscode erforderlich",
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
    res.status(200).json({ message: "Verifizierung erfolgreich!" });
  } catch (error) {
    console.error("Verifizierungsfehler:", error);
    res.status(400).json({ error: "Verifizierung fehlgeschlagen" });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: "Benutzername und Passwort erforderlich",
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

    const token = response.AuthenticationResult.IdToken;
    res.status(200).json({
      message: "Login erfolgreich",
      token,
    });
  } catch (error) {
    console.error("Login-Fehler:", error);
    res.status(400).json({ error: "Login fehlgeschlagen" });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    error: "Route nicht gefunden",
    path: req.path,
  });
});

// Server starten
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
