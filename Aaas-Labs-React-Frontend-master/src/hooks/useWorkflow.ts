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
      const response = await fetch(`${API_URL}/${id}`, {
        credentials: 'include'
      });
      if (!response.ok) throw new Error("Failed to fetch workflow");
      return await response.json();
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
      if (!response.ok) throw new Error("Failed to create workflow");
      const data = await response.json();
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
  }
};
