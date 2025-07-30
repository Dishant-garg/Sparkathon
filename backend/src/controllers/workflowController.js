const Workflow = require('../models/Workflow');
const workflowExecutionService = require('../services/workflowExecutionService');

// Helper function to transform workflow for frontend
const transformWorkflow = (workflow) => {
  return {
    id: workflow._id.toString(),
    name: workflow.name,
    userId: workflow.userId,
    nodes: workflow.nodes,
    edges: workflow.edges,
    isActive: workflow.isActive,
    schedule: workflow.schedule,
    lastExecution: workflow.lastExecution,
    createdAt: workflow.createdAt,
    updatedAt: workflow.updatedAt
  };
};

const workflowController = {
  // Get all workflows for the authenticated user
  getAllWorkflows: async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const workflows = await Workflow.find({ userId: req.user._id })
        .sort({ createdAt: -1 });

      // Transform workflows for frontend
      const transformedWorkflows = workflows.map(transformWorkflow);

      res.json(transformedWorkflows);
    } catch (error) {
      console.error('Error fetching workflows:', error);
      res.status(500).json({ error: 'Failed to fetch workflows' });
    }
  },

  // Get a specific workflow by ID
  getWorkflowById: async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const { id } = req.params;
      
      // Validate the workflow ID
      if (!id || id === 'undefined' || id === 'null') {
        return res.status(400).json({ error: 'Valid workflow ID is required' });
      }

      // Check if ID is a valid MongoDB ObjectId
      if (!id.match(/^[0-9a-fA-F]{24}$/)) {
        return res.status(400).json({ error: 'Invalid workflow ID format' });
      }

      const workflow = await Workflow.findOne({ 
        _id: id, 
        userId: req.user._id 
      });

      if (!workflow) {
        return res.status(404).json({ error: 'Workflow not found' });
      }

      // Transform the workflow for frontend
      const workflowResponse = transformWorkflow(workflow);
      
      res.json(workflowResponse);
    } catch (error) {
      console.error('Error fetching workflow:', error);
      res.status(500).json({ error: 'Failed to fetch workflow' });
    }
  },

  // Create a new workflow
  createWorkflow: async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const { name, nodes = [], edges = [] } = req.body;

      if (!name || name.trim() === '') {
        return res.status(400).json({ error: 'Workflow name is required' });
      }

      const workflow = new Workflow({
        name: name.trim(),
        userId: req.user._id,
        nodes,
        edges
      });

      const savedWorkflow = await workflow.save();
      
      // Transform the workflow to include id as string
      const workflowResponse = transformWorkflow(savedWorkflow);
      
      res.status(201).json({ workflow: workflowResponse });
    } catch (error) {
      console.error('Error creating workflow:', error);
      res.status(500).json({ error: 'Failed to create workflow' });
    }
  },

  // Update an existing workflow
  updateWorkflow: async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const { id } = req.params;
      const { name, nodes, edges, isActive, schedule } = req.body;

      // Validate the workflow ID
      if (!id || id === 'undefined' || id === 'null') {
        return res.status(400).json({ error: 'Valid workflow ID is required' });
      }

      // Check if ID is a valid MongoDB ObjectId
      if (!id.match(/^[0-9a-fA-F]{24}$/)) {
        return res.status(400).json({ error: 'Invalid workflow ID format' });
      }

      const workflow = await Workflow.findOne({ 
        _id: id, 
        userId: req.user._id 
      });

      if (!workflow) {
        return res.status(404).json({ error: 'Workflow not found' });
      }

      // Update fields if provided
      if (name !== undefined) workflow.name = name.trim();
      if (nodes !== undefined) workflow.nodes = nodes;
      if (edges !== undefined) workflow.edges = edges;
      if (isActive !== undefined) workflow.isActive = isActive;
      if (schedule !== undefined) workflow.schedule = { ...workflow.schedule, ...schedule };

      const updatedWorkflow = await workflow.save();
      // Transform the updated workflow for frontend
      const workflowResponse = transformWorkflow(updatedWorkflow);
      
      res.json(workflowResponse);
    } catch (error) {
      console.error('Error updating workflow:', error);
      res.status(500).json({ error: 'Failed to update workflow' });
    }
  },

  // Delete a workflow
  deleteWorkflow: async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const { id } = req.params;
      
      // Validate the workflow ID
      if (!id || id === 'undefined' || id === 'null') {
        return res.status(400).json({ error: 'Valid workflow ID is required' });
      }

      // Check if ID is a valid MongoDB ObjectId
      if (!id.match(/^[0-9a-fA-F]{24}$/)) {
        return res.status(400).json({ error: 'Invalid workflow ID format' });
      }

      const workflow = await Workflow.findOneAndDelete({ 
        _id: id, 
        userId: req.user._id 
      });

      if (!workflow) {
        return res.status(404).json({ error: 'Workflow not found' });
      }

      res.json({ message: 'Workflow deleted successfully' });
    } catch (error) {
      console.error('Error deleting workflow:', error);
      res.status(500).json({ error: 'Failed to delete workflow' });
    }
  },

  // Execute a workflow manually
  executeWorkflow: async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const { id } = req.params;
      
      // Validate the workflow ID
      if (!id || id === 'undefined' || id === 'null') {
        return res.status(400).json({ error: 'Valid workflow ID is required' });
      }

      // Check if ID is a valid MongoDB ObjectId
      if (!id.match(/^[0-9a-fA-F]{24}$/)) {
        return res.status(400).json({ error: 'Invalid workflow ID format' });
      }

      const workflow = await Workflow.findOne({ 
        _id: id, 
        userId: req.user._id 
      });

      if (!workflow) {
        return res.status(404).json({ error: 'Workflow not found' });
      }

      // Start workflow execution
      const executionResult = await workflowExecutionService.executeWorkflow(workflow);
      
      res.json({ 
        message: 'Workflow execution started',
        executionId: executionResult.executionId,
        status: 'running'
      });
    } catch (error) {
      console.error('Error executing workflow:', error);
      res.status(500).json({ error: 'Failed to execute workflow' });
    }
  },

  // Get workflow execution status
  getExecutionStatus: async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const { id } = req.params;
      
      // Validate the workflow ID
      if (!id || id === 'undefined' || id === 'null') {
        return res.status(400).json({ error: 'Valid workflow ID is required' });
      }

      // Check if ID is a valid MongoDB ObjectId
      if (!id.match(/^[0-9a-fA-F]{24}$/)) {
        return res.status(400).json({ error: 'Invalid workflow ID format' });
      }

      const workflow = await Workflow.findOne({ 
        _id: id, 
        userId: req.user._id 
      });

      if (!workflow) {
        return res.status(404).json({ error: 'Workflow not found' });
      }

      res.json({
        lastExecution: workflow.lastExecution || null,
        isActive: workflow.isActive,
        schedule: workflow.schedule
      });
    } catch (error) {
      console.error('Error fetching execution status:', error);
      res.status(500).json({ error: 'Failed to fetch execution status' });
    }
  },

  // Get all workflow execution results for reports
  getAllExecutionResults: async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      // Find all workflows for the user that have execution results
      const workflows = await Workflow.find({ 
        userId: req.user._id,
        lastExecution: { $exists: true, $ne: null }
      }).sort({ 'lastExecution.completedAt': -1 });

      const reports = workflows.map(workflow => {
        const execution = workflow.lastExecution;
        return {
          id: workflow._id.toString(),
          workflowId: workflow._id.toString(),
          name: workflow.name,
          status: execution.status,
          startedAt: execution.startedAt,
          completedAt: execution.completedAt,
          results: execution.results,
          error: execution.error,
          duration: execution.completedAt && execution.startedAt 
            ? execution.completedAt.getTime() - execution.startedAt.getTime()
            : null
        };
      });

      res.json({ reports });
    } catch (error) {
      console.error('Error fetching execution results:', error);
      res.status(500).json({ error: 'Failed to fetch execution results' });
    }
  }
};

module.exports = workflowController;
