import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { toast } from "sonner";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useWorkflowStore } from "@/lib/store";
import { Workflow } from "@/types/workflow";

const formSchema = z.object({
  name: z
    .string()
    .min(3, {
      message: "Workflow name must be at least 3 characters.",
    })
    .max(50, {
      message: "Workflow name must not exceed 50 characters.",
    }),
});

type FormValues = z.infer<typeof formSchema>;

interface CreateWorkflowDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const CreateWorkflowDialog = ({
  open,
  onOpenChange,
}: CreateWorkflowDialogProps) => {
  const navigate = useNavigate();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { addWorkflow, setActiveWorkflow } = useWorkflowStore();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: "",
    },
  });

  const onSubmit = async (data: FormValues) => {
    try {
      setIsSubmitting(true);

      // Create new workflow - let backend generate the ID
      const newWorkflow: Workflow = {
        id: "", // Backend will generate MongoDB ObjectId
        name: data.name,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        nodes: [],
        edges: [],
      };

      // Add to store via API
      const createdWorkflow = await addWorkflow(newWorkflow);

      

      // Validate the created workflow has a valid ID
      if (!createdWorkflow || !createdWorkflow.id || createdWorkflow.id === '') {
        throw new Error('Invalid workflow ID received from server');
      }

      setActiveWorkflow(createdWorkflow.id);

      // Success notification
      toast.success("Workflow created", {
        description: `${data.name} has been created successfully.`,
      });

      // Close dialog first
      onOpenChange(false);
      
      // Clear form
      form.reset();
      
      // Navigate with a small delay to ensure state is updated
      setTimeout(() => {
        navigate(`/workflow/${createdWorkflow.id}`);
      }, 100);
    } catch (error) {
      console.error("Error creating workflow:", error);
      toast.error("Failed to create workflow", {
        description: error instanceof Error ? error.message : "An unexpected error occurred. Please try again.",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="text-xl">Create New Workflow</DialogTitle>
          <DialogDescription>
            Give your workflow a descriptive name to get started.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form
            onSubmit={form.handleSubmit(onSubmit)}
            className="space-y-6 py-4"
          >
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Workflow Name</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="e.g., Security Scan Pipeline"
                      {...field}
                      autoFocus
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter>
              <Button
                type="submit"
                disabled={isSubmitting}
                className="w-full sm:w-auto"
              >
                {isSubmitting ? "Creating..." : "Create Workflow"}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
};

export default CreateWorkflowDialog;
