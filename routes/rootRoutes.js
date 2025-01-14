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

module.exports = router; 