import React, { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { PlusCircle, CheckCircle, Clock } from "lucide-react";

// Define type for report item
interface ReportItem {
  id: string;
  name: string;
  status: "success" | "generating";
  timestamp: Date;
}

const ReportCardPage = () => {
  // Initial reports data with proper typing
  const [reports, setReports] = useState<ReportItem[]>([
    {
      id: "github-workflow",
      name: "GitHub Workflow",
      status: "success",
      timestamp: new Date(Date.now() - 1 * 60 * 1000), // 2 minutes ago
    },
  ]);

  // Function to format relative time
  const getRelativeTime = (date: Date) => {
    const now = new Date();
    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (diffInSeconds < 60) {
      return "just now";
    } else if (diffInSeconds < 120) {
      return "1 min ago";
    } else if (diffInSeconds < 3600) {
      return `${Math.floor(diffInSeconds / 60)} mins ago`;
    } else if (diffInSeconds < 7200) {
      return "1 hour ago";
    } else if (diffInSeconds < 86400) {
      return `${Math.floor(diffInSeconds / 3600)} hours ago`;
    } else {
      return date.toLocaleDateString();
    }
  };

  // Function to add a new node when regenerate is clicked
  const handleRegenerate = (id: string) => {
    // Find the selected report and check if it exists
    const selectedReport = reports.find((report) => report.id === id);

    // Only proceed if the report was found
    if (!selectedReport) {
      console.error(`Report with id ${id} not found`);
      return;
    }

    // Create a new node based on the selected one
    const newNode: ReportItem = {
      id: `${id}-${Date.now()}`,
      name: selectedReport.name,
      status: "generating",
      timestamp: new Date(),
    };

    // Add the new node to the list
    setReports((prevReports) => [...prevReports, newNode]);

    // Simulate the generation process
    setTimeout(() => {
      setReports((prevReports) =>
        prevReports.map((report) =>
          report.id === newNode.id ? { ...report, status: "success" } : report
        )
      );
    }, 2000);
  };

  // Update timestamps every minute
  useEffect(() => {
    const interval = setInterval(() => {
      setReports((prevReports) => [...prevReports]);
    }, 60000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className={`p-6`}>
      <div className="max-w-6xl mx-auto">
        <h1 className="text-2xl font-bold mb-6">Reports</h1>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
          {reports.map((report) => (
            <Card
              key={report.id}
              className={`overflow-hidden border-none rounded-lg shadow-sm hover:shadow-md transition-all duration-300`}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-medium">{report.name}</h3>
                  {report.status === "success" ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <Clock className="h-4 w-4 text-blue-500 animate-pulse" />
                  )}
                </div>

                <div className="text-xs opacity-60 mb-3">
                  {getRelativeTime(report.timestamp)}
                </div>

                <div className="flex items-center justify-between mt-1">
                  <span
                    className={`text-xs px-2 py-1 rounded-full ${
                      report.status === "success"
                        ? "bg-green-500/20 text-green-500"
                        : "bg-blue-500/20 text-blue-500"
                    }`}
                  >
                    {report.status === "generating" ? "Generating" : "Success"}
                  </span>

                  <Button
                    size="sm"
                    variant="ghost"
                    className={`h-8 px-2 text-xs rounded-md`}
                    onClick={() => handleRegenerate(report.id)}
                    disabled={report.status === "generating"}
                  >
                    <PlusCircle className="h-3 w-3 mr-1" />
                    Regenerate
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ReportCardPage;
