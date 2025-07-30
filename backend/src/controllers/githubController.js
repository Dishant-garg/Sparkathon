const githubService = require("../services/githubService");
const User = require("../models/User");

/**
 * Get GitHub repositories of the authenticated user
 * @route GET /api/github/repos
 */
exports.getUserRepositories = async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ 
        message: "Unauthorized", 
        error: "User not authenticated" 
      });
    }

    console.log("Fetching repositories for user:", req.user.id);
    const repos = await githubService.getUserRepos(req.user.id);
    
    res.json({
      success: true,
      count: repos.length,
      data: repos
    });
  } catch (error) {
    console.error("Error in getUserRepositories:", error.message);
    res.status(500).json({ 
      success: false,
      message: "Failed to load workflows",
      error: error.message 
    });
  }
};

/**
 * API to fetch the entire code of a GitHub repository
 * @route GET /api/github/repo/:owner/:repo
 */
exports.fetchRepositoryCode = async (req, res) => {
  const { owner, repo } = req.params;

  try {
    if (!req.user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const files = await githubService.fetchRepoContents(
      owner,
      repo,
      "",
      req.user.id
    );
    res.json(files);
  } catch (error) {
    console.error("Error fetching repository code:", error);
    res.status(500).json({ message: error.message });
  }
};
