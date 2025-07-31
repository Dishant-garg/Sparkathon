const mongoose = require('mongoose');

const workflowSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  nodes: {
    type: [mongoose.Schema.Types.Mixed],
    default: [],
  },
  edges: {
    type: [mongoose.Schema.Types.Mixed],
    default: [],
  },
  isActive: {
    type: Boolean,
    default: false,
  },
  schedule: {
    frequency: {
      type: String,
      enum: ['2hr', '4hr', '6hr', '12hr', '1 day'],
    },
    enabled: {
      type: Boolean,
      default: false,
    },
    nextRun: {
      type: Date,
    },
  },
  lastExecution: {
    status: {
      type: String,
      enum: ['running', 'completed', 'failed'],
    },
    startedAt: {
      type: Date,
    },
    completedAt: {
      type: Date,
    },
    results: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    error: {
      type: String,
    },
  },
}, {
  timestamps: true,
});

// Index for efficient queries
workflowSchema.index({ userId: 1, createdAt: -1 });
workflowSchema.index({ userId: 1, isActive: 1 });

module.exports = mongoose.model('Workflow', workflowSchema);
