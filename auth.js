const crypto = require('crypto');
const { CognitoUserPool, CognitoUser, AuthenticationDetails } = require('amazon-cognito-identity-js');

// Deine Cognito-Konfiguration
const poolData = {
  UserPoolId: 'eu-central-1_7xAUfND68',
  ClientId: '74ugd216hjbmpr6jcvubmmt5i9',  // Dein ClientId
};

const userPool = new CognitoUserPool(poolData);

// Berechne den SecretHash
const calculateSecretHash = (username) => {
  const clientSecret = '65rl4qmj9bo4s9dqm0eg1hq0smnnhl9mb53pe2voc04l8r1bpd1';  // Dein Secret
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
    SecretHash: secretHash,  // Hier wird der SecretHash hinzugefügt
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
