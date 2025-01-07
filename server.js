const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const crypto = require("crypto");
const {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
} = require("@aws-sdk/client-cognito-identity-provider");

const app = express();
app.use(bodyParser.json());
app.use(cors()); // Erlaubt den Zugriff von localhost:3000 (Frontend)

// AWS Cognito konfigurieren
const cognitoClient = new CognitoIdentityProviderClient({
  region: "eu-central-1", // Deine AWS-Region
});

const CLIENT_ID = "6l2kjlrnd6klqiiddo0q5van83"; // Ersetze durch deine App-Client-ID
const CLIENT_SECRET = "1le51u3n3bs27l9856e7e0gnnc1ps3c6q9srl390ilk083gg0eju"; // Ersetze durch dein App-Client-Secret

// Berechnet den Secret-Hash für Cognito
function calculateSecretHash(username) {
  return crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(username + CLIENT_ID)
    .digest("base64");
}

// Registrierung eines Benutzers
app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;

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
    SecretHash: secretHash, // Secret-Hash hinzufügen
  };

  try {
    const command = new SignUpCommand(params);
    await cognitoClient.send(command);
    res.status(200).json({
      message:
        "Benutzer erfolgreich registriert. Überprüfen Sie Ihre E-Mail für den Verifizierungscode.",
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Verifizierung des Codes
app.post("/verify", async (req, res) => {
  const { username, code } = req.body;

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
    res.status(400).json({ error: error.message });
  }
});

// Anmeldung eines Benutzers
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const secretHash = calculateSecretHash(username);

  const params = {
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: CLIENT_ID,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
      SECRET_HASH: secretHash, // Secret-Hash hinzufügen
    },
  };

  try {
    const command = new InitiateAuthCommand(params);
    const response = await cognitoClient.send(command);
    res.status(200).json({
      message: "Login erfolgreich",
      token: response.AuthenticationResult.IdToken,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

const PORT = 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend läuft auf http://0.0.0.0:${PORT}`);
});
