const express = require('express');
const router = express.Router();
const rootMiddleware = require('../middleware/rootMiddleware');
const auth0Management = require('../config/auth0');
const QRCode = require('qrcode');

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

    // First verify the user exists
    const userResponse = await auth0Management.users.get({ id });
    const user = userResponse.data;
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get MFA token using password grant
    const tokenResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'password',
        username: user.email,
        password: password,
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        audience: `https://${process.env.AUTH0_DOMAIN}/mfa/`,
        scope: 'enroll read:authenticators remove:authenticators'
      })
    });

    const tokenData = await tokenResponse.json();

    if (tokenData.error === 'mfa_required') {
      // If MFA is required, return the mfa_token
      res.json({
        success: true,
        mfa_token: tokenData.mfa_token
      });
    } else if (!tokenResponse.ok) {
      throw new Error(tokenData.error_description || 'Invalid password');
    } else {
      // If no MFA required, return the access token
      res.json({
        success: true,
        mfa_token: tokenData.access_token
      });
    }

  } catch (error) {
    console.error('Error verifying password:', error);
    res.status(401).json({ 
      error: 'Password verification failed', 
      details: error.message 
    });
  }
});

// POST /api/users/:id/start-mfa-enrollment
router.post('/users/:id/start-mfa-enrollment', async (req, res) => {
  try {
    const { id } = req.params;
    const mfaToken = req.headers.authorization?.split(' ')[1];

    if (!mfaToken) {
      throw new Error('No MFA token provided');
    }

    console.log('Starting MFA enrollment with token:', mfaToken);

    // Start MFA enrollment using the token from password verification
    const mfaResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/mfa/associate`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'authorization': `Bearer ${mfaToken}`
      },
      body: JSON.stringify({
        authenticator_types: ['otp'],
        otp_token: {
          token_type: 'totp'
        }
      })
    });

    const responseData = await mfaResponse.json();
    console.log('MFA response:', {
      status: mfaResponse.status,
      statusText: mfaResponse.statusText,
      data: responseData
    });

    if (!mfaResponse.ok) {
      throw new Error(responseData.message || responseData.error_description || 'Failed to start MFA enrollment');
    }

    // Generate QR code data URL
    const qrCodeDataUrl = await QRCode.toDataURL(responseData.barcode_uri);

    console.log('MFA enrollment started:', responseData);

    res.json({
      success: true,
      barcode_uri: qrCodeDataUrl, // Send the QR code data URL instead of the URI
      secret: responseData.secret,
      otp_token: responseData.otp_token
    });

  } catch (error) {
    console.error('Error starting MFA enrollment:', error);
    res.status(500).json({ 
      error: 'Failed to start MFA enrollment', 
      details: error.message 
    });
  }
});

// POST /api/users/:id/verify-mfa-enrollment
router.post('/users/:id/verify-mfa-enrollment', async (req, res) => {
  try {
    const { id } = req.params;
    const { verificationCode, client_id } = req.body;
    const mfaToken = req.headers.authorization?.split(' ')[1];

    if (!verificationCode || !mfaToken) {
      throw new Error('Verification code and MFA token are required');
    }

    console.log('Verifying MFA enrollment:', {
      verificationCode,
      mfaToken
    });

    // Verify the MFA code
    const verifyResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'http://auth0.com/oauth/grant-type/mfa-otp',
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        mfa_token: mfaToken,
        otp: verificationCode
      })
    });

    const responseData = await verifyResponse.json();
    console.log('Verification response:', {
      status: verifyResponse.status,
      statusText: verifyResponse.statusText,
      data: responseData
    });

    if (!verifyResponse.ok) {
      throw new Error(responseData.error_description || 'Failed to verify MFA code');
    }

    // Get management token
    const managementToken = await getManagementToken();

    // Get current app_metadata first
    const userResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${id}`, {
      headers: {
        'Authorization': `Bearer ${managementToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const userData = await userResponse.json();
    const appMetadata = userData.app_metadata || {};
    const clientMetadata = appMetadata[client_id] || {};

    // Update only the authenticator-enabled flag
    const updateResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${id}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${managementToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        app_metadata: {
          ...appMetadata,
          [client_id]: {
            ...clientMetadata,
            'authenticator-enabled': true
          }
        }
      })
    });

    if (!updateResponse.ok) {
      throw new Error('Failed to update user metadata');
    }

    console.log('MFA verification successful');

    res.json({
      success: true,
      message: 'MFA enrollment completed successfully'
    });

  } catch (error) {
    console.error('Error verifying MFA enrollment:', error);
    res.status(500).json({ 
      error: 'Failed to verify MFA enrollment', 
      details: error.message 
    });
  }
});

// POST /api/users/:id/deactivate-mfa
router.post('/users/:id/deactivate-mfa', async (req, res) => {
  try {
    const { id } = req.params;

    const { client_id } = req.body;
    
    // Get user's enrollments to verify they have an authenticator
    const enrollments = await auth0Management.users.getEnrollments({ id });
    
    console.log('Found enrollments:', enrollments);
    
    // Find the authenticator enrollment
    const authenticatorEnrollment = enrollments.data.find(
      enrollment => enrollment.type === 'authenticator' || 
                   enrollment.auth_method === 'authenticator'
    );
    
    if (!authenticatorEnrollment) {
      throw new Error('No authenticator enrollment found');
    }

    // Delete the authenticator enrollment using the Management API
    await auth0Management.guardian.deleteGuardianEnrollment(authenticatorEnrollment);

    // Get management token for metadata update
    const managementToken = await getManagementToken();

    // Get current app_metadata first
    const userResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${id}`, {
      headers: {
        'Authorization': `Bearer ${managementToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const userData = await userResponse.json();
    const appMetadata = userData.app_metadata || {};
    const clientMetadata = appMetadata[client_id] || {};

    // Update only the authenticator-enabled flag
    await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${id}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${managementToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        app_metadata: {
          ...appMetadata,
          [client_id]: {
            ...clientMetadata,
            'authenticator-enabled': false
          }
        }
      })
    });

    res.json({
      success: true,
      message: 'Authenticator app removed successfully'
    });

  } catch (error) {
    console.error('Error deactivating MFA:', error);
    res.status(500).json({ 
      error: 'Failed to deactivate MFA', 
      details: error.message 
    });
  }
});

// GET /api/users/:id/authenticator-status
router.get('/users/:id/authenticator-status', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get user's factors using the Management API
    const response = await auth0Management.users.getEnrollments({ id });
    const enrollments = response.data;
    
    console.log('Enrollments:', enrollments);

    // Check if user has an OTP authenticator enrollment
    const hasAuthenticator = enrollments && 
                           Array.isArray(enrollments) && 
                           enrollments.some(enrollment => 
                             enrollment.type === 'authenticator' || 
                             enrollment.auth_method === 'authenticator'
                           );

    res.json({
      hasAuthenticator,
      debug: enrollments
    });

  } catch (error) {
    console.error('Error checking authenticator status:', error);
    res.status(500).json({ 
      error: 'Failed to check authenticator status', 
      details: error.message 
    });
  }
});

// Helper function to get management token
const getManagementToken = async () => {
  try {
    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        audience: `https://${process.env.AUTH0_DOMAIN}/api/v2/`,
        grant_type: 'client_credentials'
      })
    });

    if (!response.ok) {
      throw new Error('Failed to get management token');
    }

    const data = await response.json();
    return data.access_token;
  } catch (error) {
    throw error;
  }
};

// Helper function to get client secret
const getClientSecret = async (client_id) => {
  try {
    const managementToken = await getManagementToken();
    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/clients/${client_id}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${managementToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error('Failed to fetch client secret');
    }

    const data = await response.json();
    return data.client_secret;
  } catch (error) {
    throw error;
  }
};

// POST /auth0/passwordless/start
router.post('/auth0/passwordless/start', async (req, res) => {
  try {
    const { email, client_id } = req.body;

    // First get the client secret
    const client_secret = await getClientSecret(client_id);

    // Then start passwordless flow
    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/passwordless/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        client_id,
        client_secret,
        connection: 'email',
        email,
        send: 'code'
      })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error_description || data.error || 'Failed to start passwordless flow');
    }

    res.json({ message: 'Verification code sent successfully' });
  } catch (error) {
    console.error('Error in passwordless start:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /auth0/passwordless/verify
router.post('/auth0/passwordless/verify', async (req, res) => {
  try {
    const { email, code, client_id, user_id } = req.body;
    const managementToken = await getManagementToken();

    // First get the client secret
    const client_secret = await getClientSecret(client_id);

    // Then verify the code
    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        grant_type: 'http://auth0.com/oauth/grant-type/passwordless/otp',
        client_id,
        client_secret,
        username: email,
        otp: code,
        realm: 'email',
        scope: 'openid profile email'
      })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error_description || data.error || 'Invalid verification code');
    }

    // Get current app_metadata first
    const userResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${user_id}`, {
      headers: {
        'Authorization': `Bearer ${managementToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const userData = await userResponse.json();
    const appMetadata = userData.app_metadata || {};
    const clientMetadata = appMetadata[client_id] || {};

    // Update only the two-step-enabled flag
    const updateResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${user_id}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${managementToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        app_metadata: {
          ...appMetadata,
          [client_id]: {
            ...clientMetadata,
            'two-step-enabled': true
          }
        }
      })
    });

    if (!updateResponse.ok) {
      throw new Error('Failed to update user metadata');
    }

    res.json({ message: 'Two-step verification enabled successfully' });
  } catch (error) {
    console.error('Error in passwordless verify:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /auth0/revoke-access
router.post('/auth0/revoke-access', async (req, res) => {
  try {
    const { user_id, client_id } = req.body;
    const managementToken = await getManagementToken();

    // First get the user's current app_metadata
    const userResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${user_id}`, {
      headers: {
        'Authorization': `Bearer ${managementToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (!userResponse.ok) {
      throw new Error('Failed to fetch user data');
    }

    const userData = await userResponse.json();
    const appMetadata = userData.app_metadata || {};
    const allowedApps = appMetadata.allowed_apps || [];

    // Remove current client_id from allowed_apps
    const updatedAllowedApps = allowedApps.filter(app => app !== client_id);

    // Check if user has any other applications
    const hasOtherApps = updatedAllowedApps.length > 0;

    if (hasOtherApps) {
      // Update app_metadata with filtered allowed_apps and remove client_id specific data
      const updateResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${user_id}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${managementToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          app_metadata: {
            ...appMetadata,
            allowed_apps: updatedAllowedApps
          }
        })
      });

      if (!updateResponse.ok) {
        throw new Error('Failed to update user metadata');
      }
    } else {
      // Delete the user account if no other applications
      const deleteResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${user_id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${managementToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!deleteResponse.ok) {
        throw new Error('Failed to delete user account');
      }
    }

    res.json({ 
      message: hasOtherApps ? 
        'Access revoked successfully' : 
        'Account deleted successfully' 
    });
  } catch (error) {
    console.error('Error in revoke access:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /auth0/signout-devices
router.post('/auth0/signout-devices', async (req, res) => {
  try {
    const { user_id, client_id } = req.body;
    const managementToken = await getManagementToken();

    // First get current sessions for debugging
    const sessionsResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${user_id}/sessions`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${managementToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (!sessionsResponse.ok) {
      throw new Error('Failed to fetch sessions');
    }

    const sessions = await sessionsResponse.json();
    console.log('Current sessions before deletion:', sessions);

    // Delete all sessions
    const deleteResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${user_id}/sessions`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${managementToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (!deleteResponse.ok) {
      throw new Error('Failed to delete sessions');
    }

    console.log('All sessions deleted successfully');
    res.json({ success: true });
  } catch (error) {
    console.error('Error signing out from all devices:', error);
    res.status(500).json({ 
      error: 'Failed to sign out from all devices', 
      details: error.message 
    });
  }
});

module.exports = router; 