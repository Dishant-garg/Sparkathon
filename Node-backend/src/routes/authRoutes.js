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
  console.log("Redirecting to:", `${frontendUrl}/dashboard`);
  res.redirect(`${frontendUrl}/dashboard`);
});
router.get("/user", isAuthenticated, getCurrentUser);
router.get("/status", (req, res) => {
  // Check authentication status without requiring authentication
  res.json({
    isAuthenticated: req.isAuthenticated(),
    user: req.user || null,
  });
});
router.get("/logout", logoutUser);

module.exports = router;
