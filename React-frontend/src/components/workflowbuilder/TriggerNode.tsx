import { useState, useCallback, memo } from "react";
import { Handle, Position, NodeProps } from "reactflow";
import { CalendarClock, Globe, Github, AlertTriangle } from "lucide-react";
import { toast } from "sonner";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { DataSource, Frequency } from "@/types/workflow";
import { useWorkflowStore } from "@/lib/store";
import { useReactFlow } from "reactflow";
import { Input } from "@/components/ui/input";

const TriggerNode = memo(({ id, data, isConnectable }: NodeProps) => {
  const [open, setOpen] = useState(false);
  const [dataSource, setDataSource] = useState<DataSource>(
    data?.dataSource || "Domain"
  );
  const [sourceUrl, setSourceUrl] = useState(data?.sourceUrl || "");
  const [frequency, setFrequency] = useState<Frequency>(
    data?.frequency || "2hr"
  );
  const [showWarning, setShowWarning] = useState(false);
  const { setActiveDataSource } = useWorkflowStore();
  const { getNodes, getEdges, setNodes } = useReactFlow();

  const hasConnectedNodes = useCallback(() => {
    const nodes = getNodes();
    const edges = getEdges();

    return nodes.length > 1 || edges.length > 0;
  }, [getNodes, getEdges]);

  const updateNodeData = useCallback(() => {
    if (dataSource !== data?.dataSource && hasConnectedNodes()) {
      setShowWarning(true);
      return;
    }

    setNodes((nodes) =>
      nodes.map((node) => {
        if (node.id === id) {
          return {
            ...node,
            data: {
              dataSource,
              frequency,
              sourceUrl,
            },
          };
        }
        return node;
      })
    );

    setActiveDataSource(dataSource);
    toast.success("Trigger updated", {
      description: `Data source set to ${dataSource} with ${frequency} frequency`,
    });
    setOpen(false);
    setShowWarning(false);
  }, [
    dataSource,
    frequency,
    sourceUrl,
    id,
    setNodes,
    setActiveDataSource,
    hasConnectedNodes,
  ]);

  return (
    <>
      <div className="workflow-node min-w-[180px]">
        <div className="workflow-node-icon bg-[#0041cd] rounded-full">
          <CalendarClock className="w-5 h-5" />
        </div>
        <div className="workflow-node-label">Trigger</div>
        <div className="mt-2 flex flex-col items-center gap-2 text-xs text-muted-foreground">
          <div className="flex flex-row items-center gap-1">
            {dataSource === "Domain" ? (
              <Globe className="w-4 h-4" />
            ) : (
              <Github className="w-4 h-4" />
            )}
            <span>{dataSource}</span>
            <span>·</span>
            <span>{frequency}</span>
          </div>

          <span>{sourceUrl}</span>
        </div>

        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button variant="ghost" size="sm" className="mt-3 text-xs">
              Configure
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[425px]">
            <DialogHeader>
              <DialogTitle>Configure Trigger</DialogTitle>
              <DialogDescription>
                Set the data source and execution frequency for your workflow.
              </DialogDescription>
            </DialogHeader>

            {showWarning && (
              <Alert variant="destructive" className="mb-4">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>Warning</AlertTitle>
                <AlertDescription>
                  You cant change the Data source first clear all the node{" "}
                </AlertDescription>
                <div className="flex mt-4 gap-2">
                  <Button
                    variant="outline"
                    onClick={() => setShowWarning(false)}
                  >
                    Back
                  </Button>
                </div>
              </Alert>
            )}

            {!showWarning && (
              <>
                <div className="space-y-4 py-4">
                  <div className="space-y-2 w-full">
                    <label className="text-sm font-medium">Data Source</label>
                    <Select
                      value={dataSource}
                      onValueChange={(value) =>
                        setDataSource(value as DataSource)
                      }
                    >
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="Select data source" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="Domain">
                          <div className="flex items-center gap-2">
                            <Globe className="w-4 h-4" />
                            <span>Domain</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="GitHub">
                          <div className="flex items-center gap-2">
                            <Github className="w-4 h-4" />
                            <span>GitHub</span>
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium"> Source Url</label>
                    <Input
                      value={sourceUrl}
                      onChange={(e) => setSourceUrl(e.target.value)}
                      placeholder="Enter source url"
                      className="w-full"
                      name="sourceUrl"
                      id="sourceUrl"
                      type="url"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Frequency</label>
                    <Select
                      value={frequency}
                      onValueChange={(value) =>
                        setFrequency(value as Frequency)
                      }
                    >
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="Select frequency" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="2hr">Every 2 hours</SelectItem>
                        <SelectItem value="4hr">Every 4 hours</SelectItem>
                        <SelectItem value="6hr">Every 6 hours</SelectItem>
                        <SelectItem value="12hr">Every 12 hours</SelectItem>
                        <SelectItem value="1 day">Once a day</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <DialogFooter>
                  <Button type="submit" onClick={updateNodeData}>
                    Save Changes
                  </Button>
                </DialogFooter>
              </>
            )}
          </DialogContent>
        </Dialog>

        <Handle
          type="source"
          position={Position.Right}
          id="out"
          className="workflow-node-connection-point workflow-node-output"
          isConnectable={isConnectable}
        />
      </div>
    </>
  );
});

export default TriggerNode;
