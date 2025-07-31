const express = require('express');
const {
  chatWithRepository,
  createEmbeddings,
  getRepositoryAnalysis,
  getEmbeddingsStatus,
  deleteEmbeddings,
  getAllEmbeddings,
  recreateEmbeddings
} = require('../controllers/chatbotController');
const { isAuthenticated } = require('../middlewares/authMiddleware');

const router = express.Router();

// Apply authentication middleware to all routes
router.use(isAuthenticated);

// Chat with repository
router.post('/chat', chatWithRepository);

// Create embeddings for repository
router.post('/embeddings', createEmbeddings);

// Get repository analysis
router.get('/analysis/:repoId', getRepositoryAnalysis);

// Get embeddings status
router.get('/embeddings/:repoId', getEmbeddingsStatus);

// Delete embeddings
router.delete('/embeddings/:repoId', deleteEmbeddings);

// Get all embeddings
router.get('/embeddings', getAllEmbeddings);

// Recreate embeddings
router.post('/embeddings/recreate', recreateEmbeddings);

module.exports = router; 