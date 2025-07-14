require("dotenv").config();

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

console.log("FRONTEND_URL loaded:", FRONTEND_URL);

module.exports = {
  FRONTEND_URL,
};
