const express = require('express');
const router = express.Router();
const workflowController = require('../controllers/workflowController');
const { isAuthenticated } = require('../middlewares/authMiddleware');

// Apply authentication middleware to all workflow routes
router.use(isAuthenticated);

// GET /api/workflows - Get all workflows for the authenticated user
router.get('/', workflowController.getAllWorkflows);

// GET /api/workflows/reports - Get all workflow execution results for reports
router.get('/reports', workflowController.getAllExecutionResults);

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

// POST /api/workflows/:id/test - Test workflow execution (for debugging)
router.post('/:id/test', async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Test execution request for workflow: ${id}`);
    
    const workflow = await require('../models/Workflow').findById(id);
    if (!workflow) {
      return res.status(404).json({ error: 'Workflow not found' });
    }
    
    console.log('Workflow found:', workflow.name);
    console.log('Workflow nodes:', workflow.nodes?.length || 0);
    console.log('Workflow edges:', workflow.edges?.length || 0);
    
    res.json({ 
      message: 'Workflow test completed', 
      workflow: {
        id: workflow._id,
        name: workflow.name,
        nodeCount: workflow.nodes?.length || 0,
        edgeCount: workflow.edges?.length || 0,
        lastExecution: workflow.lastExecution
      }
    });
  } catch (error) {
    console.error('Test error:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
