import { Node, Edge } from "reactflow";

export type DataSource = "Domain" | "GitHub";
export type Frequency = "2hr" | "4hr" | "6hr" | "12hr" | "1 day";

export type NodeType =
  | "trigger"
  | "gobuster"
  | "nkito"
  | "nmap"
  | "sqlmap"
  | "wpscan"
  | "owasp-vulnerabilities"
  | "flow-chart"
  | "email"
  | "github-issue"
  | "slack";

export interface WorkflowNode extends Node {
  type: NodeType;
  data: any;
}

export type WorkflowEdge = Edge;

export interface TriggerData {
  dataSource: DataSource;
  url: string;
  frequency: Frequency;
}

export interface Workflow {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
}
