const Workflow = require("../models/Workflow");
const djangoScanService = require("./djangoScanService");
const notificationService = require("./notificationService");
const { v4: uuidv4 } = require("uuid");

class WorkflowExecutionService {
  constructor() {
    this.executionQueue = new Map();
  }

  /**
   * Execute a workflow
   * @param {Object} workflow - Workflow document from MongoDB
   * @returns {Promise<Object>} Execution result
   */
  async executeWorkflow(workflow) {
    const executionId = uuidv4();

    try {
      console.log(
        `Starting workflow execution: ${workflow.name} (${executionId})`
      );

      // Update workflow status
      workflow.lastExecution = {
        status: "running",
        startedAt: new Date(),
        results: {},
        error: null,
      };
      await workflow.save();

      // Store execution in queue
      this.executionQueue.set(executionId, {
        workflowId: workflow._id,
        status: "running",
        startedAt: new Date(),
      });

      // Execute workflow asynchronously
      this.executeWorkflowSteps(workflow, executionId).catch((error) => {
        console.error(`Workflow execution failed: ${executionId}`, error);
      });

      return { executionId, status: "running" };
    } catch (error) {
      console.error("Failed to start workflow execution:", error);
      throw error;
    }
  }

  /**
   * Execute workflow steps
   * @param {Object} workflow - Workflow document
   * @param {string} executionId - Execution ID
   */
  async executeWorkflowSteps(workflow, executionId) {
    try {
      const { nodes, edges } = workflow;

      // Find trigger node
      const triggerNode = nodes.find((node) => node.type === "trigger");
      if (!triggerNode) {
        throw new Error("No trigger node found in workflow");
      }

      // Get target URL from trigger
      const targetUrl = triggerNode.data?.sourceUrl || triggerNode.data?.url;
      if (!targetUrl) {
        throw new Error("No target URL specified in trigger node");
      }

      console.log(`Executing workflow for target: ${targetUrl}`);

      // Build execution graph
      const executionGraph = this.buildExecutionGraph(nodes, edges);

      // Execute nodes in sequence
      const results = await this.executeNodes(
        executionGraph,
        triggerNode.id,
        targetUrl
      );

      console.log(`Workflow execution completed successfully: ${executionId}`);
      console.log("Results:", JSON.stringify(results, null, 2));

      // Update workflow with success
      workflow.lastExecution = {
        status: "completed",
        startedAt: workflow.lastExecution.startedAt,
        completedAt: new Date(),
        results,
        error: null,
      };
      await workflow.save();

      console.log("Workflow saved with results");

      // Remove from execution queue
      this.executionQueue.delete(executionId);

      console.log(`Workflow execution completed: ${executionId}`);
    } catch (error) {
      console.error(`Workflow execution failed: ${executionId}`, error);

      // Update workflow with failure
      workflow.lastExecution = {
        status: "failed",
        startedAt: workflow.lastExecution.startedAt,
        completedAt: new Date(),
        results: {},
        error: error.message,
      };
      await workflow.save();

      // Remove from execution queue
      this.executionQueue.delete(executionId);
    }
  }

  /**
   * Build execution graph from nodes and edges
   * @param {Array} nodes - Workflow nodes
   * @param {Array} edges - Workflow edges
   * @returns {Map} Execution graph
   */
  buildExecutionGraph(nodes, edges) {
    const graph = new Map();

    // Initialize graph with nodes
    nodes.forEach((node) => {
      graph.set(node.id, {
        node,
        children: [],
        parents: [],
      });
    });

    // Add edges to graph
    edges.forEach((edge) => {
      const sourceNode = graph.get(edge.source);
      const targetNode = graph.get(edge.target);

      if (sourceNode && targetNode) {
        sourceNode.children.push(edge.target);
        targetNode.parents.push(edge.source);
      }
    });

    return graph;
  }

  /**
   * Execute nodes in the workflow
   * @param {Map} graph - Execution graph
   * @param {string} startNodeId - Starting node ID
   * @param {string} targetUrl - Target URL
   * @returns {Promise<Object>} Execution results
   */
  async executeNodes(graph, startNodeId, targetUrl) {
    const results = {};
    const executed = new Set();

    // Execute nodes using DFS
    await this.executeNodeRecursive(
      graph,
      startNodeId,
      targetUrl,
      results,
      executed
    );

    return results;
  }

  /**
   * Recursively execute nodes
   * @param {Map} graph - Execution graph
   * @param {string} nodeId - Current node ID
   * @param {string} targetUrl - Target URL
   * @param {Object} results - Results accumulator
   * @param {Set} executed - Set of executed node IDs
   * @param {Object} previousResults - Results from previous nodes
   */
  async executeNodeRecursive(
    graph,
    nodeId,
    targetUrl,
    results,
    executed,
    previousResults = null
  ) {
    if (executed.has(nodeId)) {
      return;
    }

    const graphNode = graph.get(nodeId);
    if (!graphNode) {
      return;
    }

    const { node } = graphNode;
    executed.add(nodeId);

    console.log(`Executing node: ${node.type} (${nodeId})`);

    // Execute current node - pass all results for notification nodes
    const nodeResult = await this.executeNode(
      node,
      targetUrl,
      previousResults,
      results
    );
    results[nodeId] = nodeResult;

    // Execute child nodes
    for (const childId of graphNode.children) {
      await this.executeNodeRecursive(
        graph,
        childId,
        targetUrl,
        results,
        executed,
        nodeResult
      );
    }
  }

  /**
   * Execute a single node
   * @param {Object} node - Node to execute
   * @param {string} targetUrl - Target URL
   * @param {Object} previousResults - Results from previous nodes
   * @param {Object} allResults - All results accumulated so far
   * @returns {Promise<Object>} Node execution result
   */
  async executeNode(node, targetUrl, previousResults, allResults = {}) {
    try {
      switch (node.type) {
        case "trigger":
          return {
            type: "trigger",
            success: true,
            data: { targetUrl },
            timestamp: new Date().toISOString(),
          };

        case "nmap":
          const nmapArgs = node.data?.scanArgs || "-F";
          return await djangoScanService.nmapScan(targetUrl, nmapArgs);

        case "gobuster":
          return await djangoScanService.gobusterScan(targetUrl);

        case "sqlmap":
          const sqlmapArgs = node.data?.scanArgs || "--batch --random-agent";
          return await djangoScanService.sqlmapScan(targetUrl, sqlmapArgs);

        case "wpscan":
          const wpscanArgs = node.data?.scanArgs || "--random-user-agent";
          return await djangoScanService.wpscanScan(targetUrl, wpscanArgs);

        case "email":
          // Send email notification with all scan results
          const emailConfig =
            node.data && node.data.to
              ? node.data
              : { to: "colab696969@gmail.com", from: process.env.EMAIL_USER };
          const subject = `Security Scan Results for ${targetUrl}`;

          // Collect all scan results from the workflow
          const allEmailResults = Object.values(allResults).filter(
            (r) => r && r.scanType
          );

          if (allEmailResults.length === 0) {
            return { success: false, error: "No scan results to send" };
          }

          return await notificationService.sendEmail(
            emailConfig,
            subject,
            allEmailResults
          );

        case "slack":
          // Send Slack notification with all scan results
          const slackConfig = node.data || {};
          const slackTitle = `🔍 Security Scan Alert - ${targetUrl}`;

          // Collect all scan results from the workflow
          const allSlackResults = Object.values(allResults).filter(
            (r) => r && r.scanType
          );

          if (allSlackResults.length === 0) {
            return { success: false, error: "No scan results to send" };
          }

          return await notificationService.sendSlackNotification(
            slackConfig,
            slackTitle,
            allSlackResults
          );

        case "github-issue":
          // Create GitHub issue with all scan results
          const githubConfig = node.data || {};
          const issueTitle = `Security Vulnerability Found - ${targetUrl}`;

          // Collect all scan results from the workflow
          const allGithubResults = Object.values(allResults).filter(
            (r) => r && r.scanType
          );

          if (allGithubResults.length === 0) {
            return { success: false, error: "No scan results to create issue" };
          }

          return await notificationService.createGitHubIssue(
            githubConfig,
            issueTitle,
            allGithubResults
          );

        default:
          console.warn(`Unknown node type: ${node.type}`);
          return {
            success: false,
            error: `Unknown node type: ${node.type}`,
            type: node.type,
          };
      }
    } catch (error) {
      console.error(`Node execution failed: ${node.type}`, error);
      return {
        success: false,
        error: error.message,
        type: node.type,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Get execution status
   * @param {string} executionId - Execution ID
   * @returns {Object|null} Execution status
   */
  getExecutionStatus(executionId) {
    return this.executionQueue.get(executionId) || null;
  }

  /**
   * Schedule workflow execution based on frequency
   * @param {Object} workflow - Workflow document
   */
  scheduleWorkflow(workflow) {
    if (!workflow.schedule?.enabled || !workflow.isActive) {
      return;
    }

    const { frequency } = workflow.schedule;
    const intervalMs = this.getIntervalFromFrequency(frequency);

    console.log(`Scheduling workflow: ${workflow.name} every ${frequency}`);

    setInterval(async () => {
      try {
        await this.executeWorkflow(workflow);
      } catch (error) {
        console.error(
          `Scheduled workflow execution failed: ${workflow.name}`,
          error
        );
      }
    }, intervalMs);
  }

  /**
   * Convert frequency string to milliseconds
   * @param {string} frequency - Frequency string
   * @returns {number} Interval in milliseconds
   */
  getIntervalFromFrequency(frequency) {
    const intervals = {
      "2hr": 2 * 60 * 60 * 1000,
      "4hr": 4 * 60 * 60 * 1000,
      "6hr": 6 * 60 * 60 * 1000,
      "12hr": 12 * 60 * 60 * 1000,
      "1 day": 24 * 60 * 60 * 1000,
    };

    return intervals[frequency] || intervals["2hr"];
  }
}

module.exports = new WorkflowExecutionService();
