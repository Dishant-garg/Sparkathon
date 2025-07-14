import { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  PlusCircle, 
  CheckCircle, 
  Clock, 
  XCircle, 
  Eye, 
  RefreshCw,
  AlertTriangle,
  Shield,
  Bug,
  Mail,
  MessageSquare,
  Github
} from "lucide-react";
import { workflowApi } from "@/hooks/useWorkflow";
import { toast } from "sonner";

// Define types for execution results
interface ExecutionResult {
  id: string;
  workflowId: string;
  name: string;
  status: "completed" | "failed" | "running";
  startedAt: string;
  completedAt?: string;
  results?: Record<string, any>;
  error?: string;
  duration?: number;
}

interface NodeResult {
  type: string;
  success: boolean;
  data?: any;
  error?: string;
  timestamp: string;
}

const ReportCardPage = () => {
  const [reports, setReports] = useState<ExecutionResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState<ExecutionResult | null>(null);
  const [showDetails, setShowDetails] = useState(false);

  // Fetch execution results
  const fetchReports = async () => {
    try {
      setLoading(true);
      const response = await workflowApi.getAllExecutionResults();
      setReports(response.reports || []);
    } catch (error) {
      console.error("Error fetching reports:", error);
      toast.error("Failed to load reports");
    } finally {
      setLoading(false);
    }
  };

  // Format relative time
  const getRelativeTime = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (diffInSeconds < 60) return "just now";
    if (diffInSeconds < 120) return "1 min ago";
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} mins ago`;
    if (diffInSeconds < 7200) return "1 hour ago";
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
    return date.toLocaleDateString();
  };

  // Format duration
  const formatDuration = (duration: number) => {
    if (duration < 1000) return `${duration}ms`;
    if (duration < 60000) return `${Math.floor(duration / 1000)}s`;
    return `${Math.floor(duration / 60000)}m ${Math.floor((duration % 60000) / 1000)}s`;
  };

  // Get status color and icon
  const getStatusInfo = (status: string) => {
    switch (status) {
      case "completed":
        return { 
          color: "bg-green-500/20 text-green-500", 
          icon: CheckCircle, 
          label: "Completed" 
        };
      case "failed":
        return { 
          color: "bg-red-500/20 text-red-500", 
          icon: XCircle, 
          label: "Failed" 
        };
      case "running":
        return { 
          color: "bg-blue-500/20 text-blue-500", 
          icon: Clock, 
          label: "Running" 
        };
      default:
        return { 
          color: "bg-gray-500/20 text-gray-500", 
          icon: Clock, 
          label: "Unknown" 
        };
    }
  };

  // Get node type icon
  const getNodeIcon = (type: string) => {
    switch (type) {
      case "nmap": return Shield;
      case "gobuster": return Bug;
      case "sqlmap": return AlertTriangle;
      case "wpscan": return Bug;
      case "email": return Mail;
      case "slack": return MessageSquare;
      case "github-issue": return Github;
      default: return AlertTriangle;
    }
  };

  // Re-execute workflow
  const handleReexecute = async (workflowId: string) => {
    try {
      await workflowApi.executeWorkflow(workflowId);
      toast.success("Workflow execution started");
      // Refresh reports after a delay
      setTimeout(fetchReports, 2000);
    } catch (error) {
      toast.error("Failed to execute workflow");
    }
  };

  // View report details
  const viewDetails = (report: ExecutionResult) => {
    setSelectedReport(report);
    setShowDetails(true);
  };

  useEffect(() => {
    fetchReports();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchReports, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="p-6">
        <div className="max-w-6xl mx-auto">
          <div className="flex items-center justify-center h-64">
            <RefreshCw className="h-8 w-8 animate-spin" />
            <span className="ml-2">Loading reports...</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="max-w-6xl mx-auto">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-2xl font-bold">Workflow Reports</h1>
          <Button onClick={fetchReports} variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        {reports.length === 0 ? (
          <Card>
            <CardContent className="text-center py-12">
              <Clock className="h-12 w-12 mx-auto mb-4 text-gray-400" />
              <h3 className="text-lg font-medium mb-2">No Reports Yet</h3>
              <p className="text-gray-500">Execute some workflows to see reports here.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {reports.map((report) => {
              const statusInfo = getStatusInfo(report.status);
              const StatusIcon = statusInfo.icon;
              
              return (
                <Card key={report.id} className="hover:shadow-md transition-shadow">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="font-medium truncate">{report.name}</h3>
                      <StatusIcon className={`h-4 w-4 ${
                        report.status === "completed" ? "text-green-500" :
                        report.status === "failed" ? "text-red-500" : "text-blue-500"
                      }`} />
                    </div>

                    <div className="space-y-2 mb-4">
                      <div className="text-xs text-gray-500">
                        {getRelativeTime(report.startedAt)}
                      </div>
                      
                      {report.duration && (
                        <div className="text-xs text-gray-500">
                          Duration: {formatDuration(report.duration)}
                        </div>
                      )}

                      <Badge className={`text-xs ${statusInfo.color}`}>
                        {statusInfo.label}
                      </Badge>
                    </div>

                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="flex-1"
                        onClick={() => viewDetails(report)}
                      >
                        <Eye className="h-3 w-3 mr-1" />
                        View
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleReexecute(report.workflowId)}
                      >
                        <PlusCircle className="h-3 w-3 mr-1" />
                        Run
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}

        {/* Details Modal */}
        {showDetails && selectedReport && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-4xl w-full mx-4 max-h-[80vh] overflow-hidden">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-bold">{selectedReport.name} - Results</h2>
                <Button variant="ghost" onClick={() => setShowDetails(false)}>×</Button>
              </div>
              
              <ScrollArea className="h-96">
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <strong>Status:</strong> {selectedReport.status}
                    </div>
                    <div>
                      <strong>Started:</strong> {new Date(selectedReport.startedAt).toLocaleString()}
                    </div>
                    {selectedReport.completedAt && (
                      <div>
                        <strong>Completed:</strong> {new Date(selectedReport.completedAt).toLocaleString()}
                      </div>
                    )}
                    {selectedReport.duration && (
                      <div>
                        <strong>Duration:</strong> {formatDuration(selectedReport.duration)}
                      </div>
                    )}
                  </div>

                  {selectedReport.error && (
                    <div className="bg-red-50 dark:bg-red-900/20 p-3 rounded">
                      <strong className="text-red-600">Error:</strong>
                      <pre className="text-sm mt-1 whitespace-pre-wrap">{selectedReport.error}</pre>
                    </div>
                  )}

                  {selectedReport.results && (
                    <div>
                      <h3 className="font-medium mb-2">Execution Results:</h3>
                      <div className="space-y-3">
                        {Object.entries(selectedReport.results).map(([nodeId, result]) => {
                          const nodeResult = result as NodeResult;
                          const NodeIcon = getNodeIcon(nodeResult.type);
                          
                          return (
                            <Card key={nodeId} className="p-3">
                              <div className="flex items-center gap-2 mb-2">
                                <NodeIcon className="h-4 w-4" />
                                <span className="font-medium capitalize">{nodeResult.type}</span>
                                <Badge variant={nodeResult.success ? "default" : "destructive"}>
                                  {nodeResult.success ? "Success" : "Failed"}
                                </Badge>
                              </div>
                              
                              {nodeResult.error && (
                                <div className="text-red-600 text-sm mb-2">{nodeResult.error}</div>
                              )}
                              
                              {nodeResult.data && (
                                <pre className="text-xs bg-gray-100 dark:bg-gray-700 p-2 rounded overflow-auto">
                                  {JSON.stringify(nodeResult.data, null, 2)}
                                </pre>
                              )}
                            </Card>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ReportCardPage;
