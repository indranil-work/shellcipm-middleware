const express = require('express');
const cors = require('cors');
const rootRoutes = require('./routes/rootRoutes');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api', rootRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to shellcipmpoc middleware' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 