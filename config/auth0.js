const { ManagementClient } = require('auth0');
require('dotenv').config();

const auth0Management = new ManagementClient({
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  scope: 'read:users update:users create:users delete:users'
});

module.exports = auth0Management; 