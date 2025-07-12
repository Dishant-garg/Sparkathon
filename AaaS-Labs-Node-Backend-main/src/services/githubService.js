const axios = require("axios");
const User = require("../models/User");

/**
 * Fetch GitHub repositories of an authenticated user
 * @param {string} userId - MongoDB user ID
 * @returns {Promise<Array>} - List of repositories
 */
const getUserRepos = async (userId) => {
  try {
    const user = await User.findById(userId);

    if (!user || !user.accessToken) {
      throw new Error("User not authenticated or missing access token");
    }

    console.log("Fetching repos for user:", userId);

    const response = await axios.get("https://api.github.com/user/repos", {
      headers: {
        Authorization: `Bearer ${user.accessToken}`,
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "AaaS-Labs-App"
      },
      params: {
        visibility: "all", // ✅ Fetch both public & private repositories
        per_page: 100,
        sort: "updated",
        direction: "desc"
      },
    });

    console.log(`Successfully fetched ${response.data.length} repositories`);
    return response.data;
  } catch (error) {
    console.error("Error fetching repositories:", error.response?.data || error.message);
    if (error.response?.status === 401) {
      throw new Error("GitHub access token is invalid or expired");
    }
    if (error.response?.status === 403) {
      throw new Error("GitHub API rate limit exceeded");
    }
    throw new Error(`Failed to fetch repositories: ${error.message}`);
  }
};

/**
 * Recursively fetch all files from a GitHub repository
 * @param {string} owner - Repository owner (GitHub username)
 * @param {string} repo - Repository name
 * @param {string} path - Path in the repo (default: root)
 * @param {string} accessToken - User's GitHub OAuth token
 * @returns {Promise<Array>} - List of files with content
 */
const fetchRepoContents = async (owner, repo, path = "", accessToken) => {
  try {
    const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
    const response = await axios.get(url, {
      headers: { Authorization: `Bearer ${accessToken}` },
      Accept: "application/vnd.github.v3+json",
    });

    let files = [];

    for (const item of response.data) {
      if (item.type === "file") {
        const fileResponse = await axios.get(item.download_url, {
          responseType: "arraybuffer",
        });
        const fileBuffer = Buffer.from(fileResponse.data);

        // Detect if it's a binary file
        const isBinary = fileBuffer.includes(0);
        if (isBinary) {
          console.log(`Binary file detected: ${item.path}`);
        }

        // TODO: Modify backslash "\n" in response
        files.push({
          path: item.path,
          content: isBinary
            ? fileBuffer.toString("base64")
            : fileBuffer.toString("utf-8"),
          isBinary,
        });
      } else if (item.type === "dir") {
        const subFiles = await fetchRepoContents(
          owner,
          repo,
          item.path,
          accessToken
        );
        files = files.concat(subFiles);
      }
    }

    return files;
  } catch (error) {
    console.error(
      "Error fetching repository contents:",
      error.response?.data || error.message
    );
    throw new Error("Failed to fetch repository contents");
  }
};

module.exports = { fetchRepoContents, getUserRepos };
