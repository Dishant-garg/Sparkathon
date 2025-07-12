import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  Plus,
  Calendar,
  ArrowRight,
  MoreVertical,
  Edit,
  Trash,
  Play,
} from "lucide-react";
import { toast } from "sonner";
import { format } from "date-fns";

import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import CreateWorkflowDialog from "@/components/dashboard/workflow/CreateWorkflowDialog";
import EmptyState from "@/components/dashboard/workflow/EmptyState";
import { useWorkflowStore } from "@/lib/store";
import { BACKEND_URL } from "@/lib/constant";
import { workflowApi } from "@/hooks/useWorkflow";

const Workflow = () => {
  const navigate = useNavigate();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const {
    workflows,
    isLoading,
    error,
    fetchWorkflows,
    deleteWorkflow,
    setActiveWorkflow,
  } = useWorkflowStore();

  useEffect(() => {
    fetchWorkflows();
  }, [fetchWorkflows]);

  const handleCreateWorkflow = () => {
    setDialogOpen(true);
  };

  const handleDeleteWorkflow = async (
    id: string,
    name: string,
    e: React.MouseEvent
  ) => {
    e.stopPropagation();
    if (confirm(`Are you sure you want to delete "${name}"?`)) {
      try {
        await deleteWorkflow(id);
        toast.success("Workflow deleted", {
          description: `${name} has been deleted successfully.`,
        });
      } catch (error) {
        // Error is already handled in the store with a toast
      }
    }
  };

  const handleEditWorkflow = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setActiveWorkflow(id);
    navigate(`/workflow/${id}`);
  };

  const handleExecuteWorkflow = async (
    id: string,
    name: string,
    e: React.MouseEvent
  ) => {
    e.stopPropagation();

    try {
      const response = await fetch(
        `${BACKEND_URL}/api/workflows/${id}/execute`,
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
        }
      );

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({
          error: "Unknown error",
        }));
        throw new Error(
          errorData.error || `HTTP ${response.status}: Failed to execute workflow`
        );
      }

      const result = await response.json();

      toast.success("Workflow execution started", {
        description: `"${name}" is now executing. Check Reports for results.`,
        duration: 5000,
      });

      console.log("Workflow execution result:", result);
    } catch (error) {
      console.error("Error executing workflow:", error);
      toast.error("Failed to execute workflow", {
        description:
          error instanceof Error ? error.message : "An unexpected error occurred",
      });
    }
  };

  const handleCardClick = (id: string) => {
    setActiveWorkflow(id);
    navigate(`/workflow/${id}`);
  };

  const filteredWorkflows = workflows.filter((workflow) =>
    workflow.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <>
      <div className="container mx-auto px-4 pt-20 pb-10">
        <div className="flex flex-col space-y-8 animate-fade-in">
          {/* Page header */}
          <div className="flex flex-col md:flex-row justify-between md:items-center gap-4">
            <h1 className="text-3xl font-bold tracking-tight">Workflows</h1>
            <div className="flex gap-3">
              <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                <Input
                  placeholder="Search workflows..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-9 max-w-xs"
                />
              </div>
              <Button onClick={handleCreateWorkflow}>
                <Plus className="w-4 h-4 mr-2" />
                Create Workflow
              </Button>
            </div>
          </div>

          {/* Loading and error states */}
          {isLoading && (
            <div className="flex justify-center py-16">
              <p className="text-muted-foreground">Loading workflows...</p>
            </div>
          )}

          {error && !isLoading && (
            <div className="flex justify-center py-16">
              <div className="text-center">
                <p className="text-destructive mb-2">{error}</p>
                <Button variant="outline" onClick={() => fetchWorkflows()}>
                  Try Again
                </Button>
              </div>
            </div>
          )}

          {/* Workflows list */}
          {!isLoading && !error && (
            <>
              {" "}
              {/* Workflows list */}
              {workflows.length === 0 ? (
                <div className="flex justify-center py-16">
                  <EmptyState
                    title="No workflows yet"
                    description="Create your first workflow to get started."
                    buttonText="Create Workflow"
                    onClick={handleCreateWorkflow}
                    icon={<Calendar className="w-8 h-8" />}
                  />
                </div>
              ) : filteredWorkflows.length === 0 ? (
                <div className="flex justify-center py-16">
                  <EmptyState
                    title="No matching workflows"
                    description={`No workflows found matching "${searchTerm}"`}
                    icon={<Search className="w-8 h-8" />}
                  />
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {filteredWorkflows.map((workflow) => (
                    <Card
                      key={workflow.id}
                      className="overflow-hidden transition-all duration-300 hover:shadow-lg cursor-pointer group bg-gradient-to-br from-background to-muted/50 border-muted/30"
                      onClick={() => handleCardClick(workflow.id)}
                    >
                      <CardContent className="p-6">
                        <div className="flex justify-between items-start">
                          <div className="space-y-4">
                            <div className="flex items-center space-x-2">
                              <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center">
                                <Calendar className="w-4 h-4 text-primary" />
                              </div>
                              <h3 className="font-semibold text-lg group-hover:text-primary transition-colors">
                                {workflow.name}
                              </h3>
                            </div>
                            <div className="flex items-center text-sm text-muted-foreground">
                              <Calendar className="w-3.5 h-3.5 mr-1.5 opacity-70" />
                              {format(
                                new Date(workflow.createdAt),
                                "MMM d, yyyy"
                              )}
                            </div>
                          </div>
                          <DropdownMenu>
                            <DropdownMenuTrigger
                              asChild
                              onClick={(e) => e.stopPropagation()}
                            >
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity"
                              >
                                <MoreVertical className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem
                                onClick={(e) =>
                                  handleExecuteWorkflow(
                                    workflow.id,
                                    workflow.name,
                                    e as React.MouseEvent
                                  )
                                }
                              >
                                <Play className="mr-2 h-4 w-4" />
                                Execute
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={(e) =>
                                  handleEditWorkflow(
                                    workflow.id,
                                    e as React.MouseEvent
                                  )
                                }
                              >
                                <Edit className="mr-2 h-4 w-4" />
                                Edit
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                className="text-destructive focus:text-destructive"
                                onClick={(e) =>
                                  handleDeleteWorkflow(
                                    workflow.id,
                                    workflow.name,
                                    e as React.MouseEvent
                                  )
                                }
                              >
                                <Trash className="mr-2 h-4 w-4" />
                                Delete
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </CardContent>
                      <CardFooter className="px-6 py-4 border-t border-muted/20 bg-muted/5">
                        <div className="flex items-center justify-between w-full">
                          <div className="flex items-center">
                            <div className="h-2 w-2 rounded-full bg-green-500 mr-2" />
                            <span className="text-xs text-muted-foreground">
                              Active
                            </span>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-xs group-hover:text-primary transition-colors hover:bg-transparent"
                            onClick={(e) =>
                              handleExecuteWorkflow(
                                workflow.id,
                                workflow.name,
                                e as React.MouseEvent
                              )
                            }
                          >
                            Open workflow
                            <ArrowRight className="w-3.5 h-3.5 ml-1.5 transition-transform group-hover:translate-x-1" />
                          </Button>
                        </div>
                      </CardFooter>
                    </Card>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
      <CreateWorkflowDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </>
  );
};

export default Workflow;
