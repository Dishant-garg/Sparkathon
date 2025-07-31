const express = require("express");
const {
  githubAuth,
  githubAuthCallback,
  getCurrentUser,
  logoutUser,
} = require("../controllers/authController");
const { isAuthenticated } = require("../middlewares/authMiddleware");
require("dotenv").config();

const router = express.Router();

router.get("/github", githubAuth);
router.get("/github/callback", githubAuthCallback, (req, res) => {
  // Use environment variable directly with fallback
  const frontendUrl = process.env.FRONTEND_URL || "http://localhost:5173";
  console.log("GitHub callback completed - User:", req.user ? req.user.username : 'null');
  console.log("Redirecting to:", `${frontendUrl}/dashboard`);
  res.redirect(`${frontendUrl}/dashboard`);
});
router.get("/user", isAuthenticated, getCurrentUser);
router.get("/status", (req, res) => {
  // Check authentication status without requiring authentication
  console.log("Auth status check - Session:", req.sessionID);
  console.log("Auth status check - IsAuthenticated:", req.isAuthenticated());
  console.log("Auth status check - User:", req.user ? req.user.username : 'null');
  
  res.json({
    isAuthenticated: req.isAuthenticated(),
    user: req.user || null,
    sessionId: req.sessionID,
    sessionData: req.session
  });
});
router.get("/logout", logoutUser);

module.exports = router;
