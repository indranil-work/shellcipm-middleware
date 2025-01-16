const express = require('express');
const router = express.Router();
const rootMiddleware = require('../middleware/rootMiddleware');
const auth0Management = require('../config/auth0');

// Apply middleware to all routes in this router
router.use(rootMiddleware);

// GET /api/status
router.get('/status', (req, res) => {
  res.json({
    status: 'active',
    timestamp: req.requestTime,
    version: '1.0.0'
  });
});

// GET /api/health
router.get('/health', (req, res) => {
  res.json({
    health: 'ok',
    uptime: process.uptime()
  });
});

// GET /api/users
router.get('/users', async (req, res) => {
  try {
    const users = await auth0Management.users.getAll({
      per_page: 100,
      page: 0,
      include_totals: true
    });
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users', details: error.message });
  }
});

// GET /api/users/:id
router.get('/users/:id', async (req, res) => {
  try {
    const user = await auth0Management.users.get({ id: req.params.id });
    res.json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user', details: error.message });
  }
});

// POST /api/users/:id/personal-details
router.post('/users/:id/personal-details', async (req, res) => {
  try {
    const { id } = req.params;
    const { firstName, lastName, email, phoneNumber } = req.body;

    // Update user metadata in Auth0
    const updatedUser = await auth0Management.users.update({ id }, {
      user_metadata: {
        firstName,
        lastName,
        phoneNumber
      },
      email: email
    });

    res.json({
      success: true,
      user: updatedUser
    });
  } catch (error) {
    console.error('Error updating user details:', error);
    res.status(500).json({ error: 'Failed to update user details', details: error.message });
  }
});

// POST /api/users/:id/communications
router.post('/users/:id/communications', async (req, res) => {
  try {
    const { id } = req.params;
    const { preferences } = req.body;  // expecting an array of preferences

    // Update app_metadata in Auth0
    const updatedUser = await auth0Management.users.update({ id }, {
      app_metadata: {
        communications_preference: preferences || []  // if preferences is undefined, use empty array
      }
    });

    res.json({
      success: true,
      user: updatedUser
    });
  } catch (error) {
    console.error('Error updating communications preferences:', error);
    res.status(500).json({ 
      error: 'Failed to update communications preferences', 
      details: error.message 
    });
  }
});

// POST /api/users/:id/change-password
router.post('/users/:id/change-password', async (req, res) => {
  try {
    const { id } = req.params;
    const { currentPassword, newPassword } = req.body;

    // First verify the current password
    const verifyPasswordResponse = await auth0Management.users.getAll({
      q: `user_id:"${id}"`,
      search_engine: 'v3'
    });

    if (!verifyPasswordResponse || verifyPasswordResponse.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Change the password using Auth0 Management API
    const updatedUser = await auth0Management.users.update({ id }, {
      password: newPassword,
      connection: 'shelldemoconnection'  // specify your connection name
    });

    res.json({
      success: true,
      message: 'Password updated successfully'
    });

  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ 
      error: 'Failed to change password', 
      details: error.message 
    });
  }
});

// GET /api/password-policy
router.get('/password-policy', async (req, res) => {
  try {
    // Get all connections to find the shelldemoconnection
    const response = await auth0Management.connections.getAll({
      strategy: 'auth0'
    });

    // Find the specific connection in the data array
    const connection = response.data.find(conn => 
      conn.name === 'shelldemoconnection'
    );

    if (!connection) {
      throw new Error('Database connection not found');
    }

    // Extract password policy from the connection
    const passwordPolicy = {
      min_length: connection.options?.password_complexity_options?.min_length || 8,
      requires_uppercase: connection.options?.passwordPolicy === 'good',
      requires_lowercase: connection.options?.passwordPolicy === 'good',
      requires_numbers: connection.options?.passwordPolicy === 'good',
      requires_symbols: connection.options?.passwordPolicy === 'good'
    };

    console.log('Extracted password policy:', {
      connection: connection.name,
      policy: passwordPolicy,
      rawPasswordPolicy: connection.options?.passwordPolicy,
      rawComplexityOptions: connection.options?.password_complexity_options
    });

    res.json({
      success: true,
      policy: passwordPolicy
    });

  } catch (error) {
    console.error('Error fetching password policy:', error);
    res.status(500).json({ 
      error: 'Failed to fetch password policy', 
      details: error.message 
    });
  }
});

// POST /api/users/:id/change-email
router.post('/users/:id/change-email', async (req, res) => {
  try {
    const { id } = req.params;
    const { newEmail, password } = req.body;

    // First verify the user exists
    const user = await auth0Management.users.get({ id });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if the new email is already in use
    const existingUsers = await auth0Management.users.getAll({
      q: `email:"${newEmail}"`,
      search_engine: 'v3'
    });

    if (existingUsers && existingUsers.length > 0) {
      return res.status(400).json({ 
        error: 'Email already in use',
        code: 'email_exists'
      });
    }

    // Update the email using Auth0 Management API
    const updatedUser = await auth0Management.users.update(
      { id }, 
      {
        email: newEmail,
        email_verified: false, // Reset email verification status
        verify_email: true,    // Trigger verification email
        connection: 'shelldemoconnection'
      }
    );

    console.log('Email update response:', {
      userId: id,
      oldEmail: user.email,
      newEmail,
      updatedUser
    });

    res.json({
      success: true,
      message: 'Email updated successfully. Please verify your new email address.',
      user: {
        email: newEmail,
        email_verified: false
      }
    });

  } catch (error) {
    console.error('Error changing email:', error);
    
    // Handle specific error cases
    if (error.message.includes('email_exists')) {
      return res.status(400).json({ 
        error: 'Email already in use',
        code: 'email_exists'
      });
    }

    res.status(500).json({ 
      error: 'Failed to change email', 
      details: error.message,
      code: 'change_email_failed'
    });
  }
});

// GET /api/users/:id/email-settings
router.get('/users/:id/email-settings', async (req, res) => {
  try {
    const { id } = req.params;

    // Get connection settings to check email verification requirements
    const connections = await auth0Management.connections.getAll({
      strategy: 'auth0'
    });

    const connection = connections.data.find(conn => 
      conn.name === 'shelldemoconnection'
    );

    if (!connection) {
      throw new Error('Database connection not found');
    }

    // Extract email settings
    const emailSettings = {
      requires_verification: connection.options?.requires_verification || false,
      verification_method: connection.options?.verification?.method || 'code',
      minimum_length: 5, // Default minimum email length
      allowed_domains: connection.options?.allowed_domains || [],
      blocked_domains: connection.options?.blocked_domains || []
    };

    console.log('Email settings:', {
      connection: connection.name,
      settings: emailSettings
    });

    res.json({
      success: true,
      settings: emailSettings
    });

  } catch (error) {
    console.error('Error fetching email settings:', error);
    res.status(500).json({ 
      error: 'Failed to fetch email settings', 
      details: error.message 
    });
  }
});

// POST /api/users/:id/resend-email-verification
router.post('/users/:id/resend-email-verification', async (req, res) => {
  try {
    const { id } = req.params;
    const { email } = req.body;

    // Verify the user exists
    const user = await auth0Management.users.get({ id });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Trigger a new verification email
    await auth0Management.jobs.verifyEmail({
      user_id: id,
      client_id: process.env.AUTH0_CLIENT_ID
    });

    res.json({
      success: true,
      message: 'Verification email sent successfully'
    });

  } catch (error) {
    console.error('Error resending verification email:', error);
    res.status(500).json({ 
      error: 'Failed to resend verification email', 
      details: error.message 
    });
  }
});

// POST /api/users/:id/verify-password
router.post('/users/:id/verify-password', async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;

    // First verify the user exists and log the full user object
    const userResponse = await auth0Management.users.get({ id });
    const user = userResponse.data;  // Extract the data object
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('User details:', { 
      userId: id, 
      email: user.email,
      name: user.name,
      identities: user.identities,
      connection: 'shelldemoconnection'
    });

    if (!user.email) {
      throw new Error('User email not found in profile');
    }

    // Verify password using Auth0's /oauth/token endpoint
    const tokenUrl = `https://${process.env.AUTH0_DOMAIN}/oauth/token`;
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        grant_type: 'password',
        username: user.email,
        password: password,
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        scope: 'openid profile email',
        realm: 'shelldemoconnection'
      })
    });

    const data = await response.json();

    console.log('Auth0 response:', {
      status: response.status,
      data: data
    });

    if (!response.ok) {
      if (response.status === 401 || data.error === 'invalid_grant') {
        return res.status(401).json({
          error: 'Invalid password',
          code: 'invalid_password'
        });
      }
      throw new Error(data.error_description || data.error || 'Failed to verify password');
    }

    res.json({
      success: true,
      message: 'Password verified successfully'
    });

  } catch (error) {
    console.error('Error verifying password:', error);
    
    if (error.message.includes('invalid_grant')) {
      return res.status(401).json({
        error: 'Invalid password',
        code: 'invalid_password'
      });
    }

    res.status(500).json({ 
      error: 'Failed to verify password', 
      details: error.message 
    });
  }
});

module.exports = router; 