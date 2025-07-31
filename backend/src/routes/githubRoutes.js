const express = require("express");
const {
  getUserRepositories,
  fetchRepositoryCode,
} = require("../controllers/githubController");
const { isAuthenticated } = require("../middlewares/authMiddleware");

const router = express.Router();

router.get("/repos", isAuthenticated, getUserRepositories);
router.get("/repo/:owner/:repo", isAuthenticated, fetchRepositoryCode);

module.exports = router;
