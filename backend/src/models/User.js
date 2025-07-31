const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  githubId: {
    type: String,
    required: true,
    unique: true,
  },
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    sparse: true, // Allows null values but enforces uniqueness when present
  },
  avatar: {
    type: String,
  },
  accessToken: {
    type: String,
  },
  profileUrl: {
    type: String,
  },
}, {
  timestamps: true,
});

module.exports = mongoose.model('User', userSchema);
