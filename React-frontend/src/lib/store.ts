import { create } from "zustand";
import { DataSource, Workflow } from "@/types/workflow";
import { workflowApi } from "@/hooks/useWorkflow";
import { toast } from "sonner";

interface WorkflowStore {
  workflows: Workflow[];
  isLoading: boolean;
  error: string | null;
  activeWorkflowId: string | null;
  activeDataSource: DataSource | null;

  // Actions
  fetchWorkflows: () => Promise<void>;
  fetchWorkflowById: (id: string) => Promise<Workflow | null>;
  addWorkflow: (workflow: Workflow) => Promise<Workflow>;
  updateWorkflow: (workflow: Workflow) => Promise<void>;
  deleteWorkflow: (id: string) => Promise<void>;
  setActiveWorkflow: (id: string | null) => void;
  setActiveDataSource: (dataSource: DataSource | null) => void;
}

export const useWorkflowStore = create<WorkflowStore>()((set) => ({
  workflows: [],
  isLoading: false,
  error: null,
  activeWorkflowId: null,
  activeDataSource: null,

  fetchWorkflows: async () => {
    set({ isLoading: true, error: null });
    try {
      const workflows = await workflowApi.getAllWorkflows();
      set({ workflows, isLoading: false });
    } catch (error) {
      console.error("Failed to fetch workflows:", error);
      set({
        error: "Failed to load workflows. Please try again.",
        isLoading: false,
      });
      toast.error("Failed to load workflows");
    }
  },

  fetchWorkflowById: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      const workflow = await workflowApi.getWorkflowById(id);
      // Update the workflow in the store if it exists
      set((state) => ({
        workflows: state.workflows.some(w => w.id === workflow.id) 
          ? state.workflows.map((w) => w.id === workflow.id ? workflow : w)
          : [...state.workflows, workflow],
        isLoading: false,
      }));
      return workflow;
    } catch (error) {
      console.error(`Failed to fetch workflow ${id}:`, error);
      set({
        error: `Failed to load workflow. Please try again.`,
        isLoading: false,
      });
      toast.error("Failed to load workflow");
      return null;
    }
  },

  addWorkflow: async (workflow: Workflow) => {
    set({ isLoading: true, error: null });
    try {
      const newWorkflow = await workflowApi.createWorkflow(workflow);
      set((state) => ({
        workflows: [...state.workflows, newWorkflow],
        isLoading: false,
      }));
      return newWorkflow;
    } catch (error) {
      console.error("Failed to create workflow:", error);
      set({
        error: "Failed to create workflow. Please try again.",
        isLoading: false,
      });
      toast.error("Failed to create workflow");
      throw error;
    }
  },

  updateWorkflow: async (workflow: Workflow) => {
    set({ isLoading: true, error: null });
    try {
      const updatedWorkflow = await workflowApi.updateWorkflow(workflow);
      set((state) => ({
        workflows: state.workflows.map((w) =>
          w.id === updatedWorkflow.id ? updatedWorkflow : w
        ),
        isLoading: false,
      }));
    } catch (error) {
      console.error("Failed to update workflow:", error);
      set({
        error: "Failed to update workflow. Please try again.",
        isLoading: false,
      });
      toast.error("Failed to update workflow");
      throw error;
    }
  },

  deleteWorkflow: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      await workflowApi.deleteWorkflow(id);
      set((state) => ({
        workflows: state.workflows.filter((w) => w.id !== id),
        activeWorkflowId:
          state.activeWorkflowId === id ? null : state.activeWorkflowId,
        isLoading: false,
      }));
    } catch (error) {
      console.error(`Failed to delete workflow ${id}:`, error);
      set({
        error: "Failed to delete workflow. Please try again.",
        isLoading: false,
      });
      toast.error("Failed to delete workflow");
      throw error;
    }
  },

  setActiveWorkflow: (id) => set({ activeWorkflowId: id }),
  setActiveDataSource: (dataSource) => set({ activeDataSource: dataSource }),
}));
