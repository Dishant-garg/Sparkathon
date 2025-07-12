const mongoose = require('mongoose');

const workflowNodeSchema = new mongoose.Schema({
  id: { type: String, required: true },
  type: { 
    type: String, 
    required: true,
    enum: [
      'trigger', 'gobuster', 'nkito', 'nmap', 'sqlmap', 
      'wpscan', 'owasp-vulnerabilities', 'flow-chart', 
      'email', 'github-issue', 'slack'
    ]
  },
  data: { type: mongoose.Schema.Types.Mixed, default: {} },
  position: {
    x: { type: Number, required: true },
    y: { type: Number, required: true }
  }
});

const workflowEdgeSchema = new mongoose.Schema({
  id: { type: String, required: true },
  source: { type: String, required: true },
  target: { type: String, required: true },
  sourceHandle: { type: String },
  targetHandle: { type: String }
});

const workflowExecutionSchema = new mongoose.Schema({
  status: { 
    type: String, 
    enum: ['pending', 'running', 'completed', 'failed'], 
    default: 'pending' 
  },
  startedAt: { type: Date },
  completedAt: { type: Date },
  results: { type: mongoose.Schema.Types.Mixed, default: {} },
  error: { type: String }
});

const workflowSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true,
    trim: true 
  },
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  nodes: [workflowNodeSchema],
  edges: [workflowEdgeSchema],
  isActive: { 
    type: Boolean, 
    default: false 
  },
  lastExecution: workflowExecutionSchema,
  schedule: {
    frequency: { 
      type: String, 
      enum: ['2hr', '4hr', '6hr', '12hr', '1 day'],
      default: '2hr'
    },
    enabled: { type: Boolean, default: false }
  }
}, {
  timestamps: true
});

// Index for efficient querying
workflowSchema.index({ userId: 1, createdAt: -1 });
workflowSchema.index({ 'schedule.enabled': 1, isActive: 1 });

module.exports = mongoose.model('Workflow', workflowSchema);
