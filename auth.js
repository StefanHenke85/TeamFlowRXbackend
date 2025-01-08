const crypto = require('crypto');
const { CognitoUserPool, CognitoUser, AuthenticationDetails } = require('amazon-cognito-identity-js');

// Deine Cognito-Konfiguration
const poolData = {
  UserPoolId: 'eu-central-1_4V15wCUMe',
  ClientId: '6l2kjlrnd6klqiiddo0q5van83',  // Dein ClientId
};

const userPool = new CognitoUserPool(poolData);

// Berechne den SecretHash
const calculateSecretHash = (username) => {
  const clientSecret = '1le51u3n3bs27l9856e7e0gnnc1ps3c6q9srl390ilk083gg0eju';  // Dein Secret
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
