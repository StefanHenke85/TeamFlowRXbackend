require('dotenv').config(); // Lädt Umgebungsvariablen aus der .env-Datei
const crypto = require('crypto');
const { CognitoUserPool, CognitoUser, AuthenticationDetails } = require('amazon-cognito-identity-js');

// Cognito-Konfiguration aus Umgebungsvariablen
const poolData = {
  UserPoolId: process.env.COGNITO_USER_POOL_ID, // Cognito User Pool ID
  ClientId: process.env.COGNITO_CLIENT_ID,     // Cognito Client ID
};

const userPool = new CognitoUserPool(poolData);

// Berechne den SecretHash
const calculateSecretHash = (username) => {
  const clientSecret = process.env.COGNITO_CLIENT_SECRET; // Cognito Client Secret
  return crypto
    .createHmac('sha256', clientSecret)
    .update(username + poolData.ClientId)
    .digest('base64');
};

// Login-Funktion
const loginUser = (username, password) => {
  const secretHash = calculateSecretHash(username);
  const authenticationDetails = new AuthenticationDetails({
    Username: username,
    Password: password,
    SecretHash: secretHash, // Hier wird der SecretHash hinzugefügt
  });

  const cognitoUser = new CognitoUser({
    Username: username,
    Pool: userPool,
  });

  cognitoUser.authenticateUser(authenticationDetails, {
    onSuccess: (result) => {
      console.log('Login erfolgreich:', result);
    },
    onFailure: (err) => {
      console.error('Login fehlgeschlagen:', err);
    },
  });
};

// Exportiere die Funktion
module.exports = { loginUser };
