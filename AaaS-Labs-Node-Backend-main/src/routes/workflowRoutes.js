const express = require('express');
const router = express.Router();
const workflowController = require('../controllers/workflowController');
const { isAuthenticated } = require('../middlewares/authMiddleware');

// Apply authentication middleware to all workflow routes
router.use(isAuthenticated);

// GET /api/workflows - Get all workflows for the authenticated user
router.get('/', workflowController.getAllWorkflows);

// GET /api/workflows/:id - Get a specific workflow by ID
router.get('/:id', workflowController.getWorkflowById);

// POST /api/workflows - Create a new workflow
router.post('/', workflowController.createWorkflow);

// PUT /api/workflows/:id - Update a workflow
router.put('/:id', workflowController.updateWorkflow);

// DELETE /api/workflows/:id - Delete a workflow
router.delete('/:id', workflowController.deleteWorkflow);

// POST /api/workflows/:id/execute - Execute a workflow manually
router.post('/:id/execute', workflowController.executeWorkflow);

// GET /api/workflows/:id/status - Get workflow execution status
router.get('/:id/status', workflowController.getExecutionStatus);

module.exports = router;
