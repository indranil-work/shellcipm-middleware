const rootMiddleware = (req, res, next) => {
  // Add timestamp to request
  req.requestTime = new Date().toISOString();
  
  // Log request
  console.log(`${req.method} ${req.url} at ${req.requestTime}`);
  
  next();
};

module.exports = rootMiddleware; 