import { BACKEND_URL } from "@/lib/constant";
import { Workflow } from "@/types/workflow";

const API_URL = `${BACKEND_URL}/api/workflows`;

export const workflowApi = {
  getAllWorkflows: async (): Promise<Workflow[]> => {
    try {
      const response = await fetch(API_URL, {
        credentials: 'include'
      });
      if (!response.ok) throw new Error("Failed to fetch workflows");
      return await response.json();
    } catch (error) {
      console.error("Error fetching workflows:", error);
      throw error;
    }
  },

  getWorkflowById: async (id: string): Promise<Workflow> => {
    try {
      // Validate ID before making request
      if (!id || id === 'undefined' || id === 'null' || id.trim() === '') {
        throw new Error("Invalid workflow ID provided");
      }

      if (!id.match(/^[0-9a-fA-F]{24}$/)) {
        throw new Error("Invalid workflow ID format");
      }

      const response = await fetch(`${API_URL}/${id}`, {
        credentials: 'include'
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: "Unknown error" }));
        if (response.status === 404) {
          throw new Error("Workflow not found");
        }
        throw new Error(errorData.error || `HTTP ${response.status}: Failed to fetch workflow`);
      }
      
      const workflow = await response.json();
      
      // Validate response
      if (!workflow || !workflow.id) {
        throw new Error("Invalid workflow data received");
      }
      
      return workflow;
    } catch (error) {
      console.error(`Error fetching workflow ${id}:`, error);
      throw error;
    }
  },

  createWorkflow: async (workflow: Workflow): Promise<Workflow> => {
    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: 'include',
        body: JSON.stringify(workflow),
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: "Unknown error" }));
        throw new Error(errorData.error || `HTTP ${response.status}: Failed to create workflow`);
      }
      
      const data = await response.json();
      
      // Validate response structure
      if (!data.workflow) {
        throw new Error("Invalid response: workflow data missing");
      }
      
      if (!data.workflow.id || data.workflow.id === '') {
        throw new Error("Invalid response: workflow ID missing or empty");
      }
      
      return data.workflow;
    } catch (error) {
      console.error("Error creating workflow:", error);
      throw error;
    }
  },

  updateWorkflow: async (workflow: Workflow): Promise<Workflow> => {
    try {
      const response = await fetch(`${API_URL}/${workflow.id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: 'include',
        body: JSON.stringify(workflow),
      });
      if (!response.ok) throw new Error("Failed to update workflow");
      return await response.json();
    } catch (error) {
      console.error(`Error updating workflow ${workflow.id}:`, error);
      throw error;
    }
  },

  deleteWorkflow: async (id: string): Promise<void> => {
    try {
      const response = await fetch(`${API_URL}/${id}`, {
        method: "DELETE",
        credentials: 'include'
      });
      if (!response.ok) throw new Error("Failed to delete workflow");
    } catch (error) {
      console.error(`Error deleting workflow ${id}:`, error);
      throw error;
    }
  },

  executeWorkflow: async (id: string): Promise<any> => {
    try {
      const response = await fetch(`${API_URL}/${id}/execute`, {
        method: "POST",
        credentials: 'include'
      });
      if (!response.ok) throw new Error("Failed to execute workflow");
      return await response.json();
    } catch (error) {
      console.error(`Error executing workflow ${id}:`, error);
      throw error;
    }
  },

  getExecutionStatus: async (id: string): Promise<any> => {
    try {
      const response = await fetch(`${API_URL}/${id}/status`, {
        credentials: 'include'
      });
      if (!response.ok) throw new Error("Failed to get execution status");
      return await response.json();
    } catch (error) {
      console.error(`Error getting execution status ${id}:`, error);
      throw error;
    }
  },

  getAllExecutionResults: async (): Promise<any> => {
    try {
      const response = await fetch(`${API_URL}/reports`, {
        credentials: 'include'
      });
      if (!response.ok) throw new Error("Failed to get execution results");
      return await response.json();
    } catch (error) {
      console.error("Error getting execution results:", error);
      throw error;
    }
  }
};
