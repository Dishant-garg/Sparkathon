/**
 * Middleware to check if user is authenticated
 */
exports.isAuthenticated = (req, res, next) => {
  console.log("Authentication check:", {
    isAuthenticated: req.isAuthenticated(),
    hasUser: !!req.user,
    sessionID: req.sessionID,
    userId: req.user?._id || 'none'
  });
  
  if (req.isAuthenticated()) {
    return next();
  }
  
  console.log("Authentication failed - sending 401");
  res.status(401).json({ message: "Unauthorized" });
};
