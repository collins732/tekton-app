// Types pour le système de scan

export interface ScanTarget {
  url: string;
  scanId: string;
}

export interface PortScanResult {
  port: number;
  state: 'open' | 'closed' | 'filtered';
  service?: string;
}

export interface TechnologyInfo {
  name: string;
  version?: string;
  category: 'server' | 'framework' | 'language' | 'cms' | 'other';
}

export interface Vulnerability {
  type: 'xss' | 'sqli' | 'security-header' | 'info' | 'config'; // Added 'security-header'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location?: string;
  evidence?: string;
}

export interface ScanResult {
  scanId: string;
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt: Date;
  completedAt?: Date;
  progress: number;
  currentStep?: string;
  results: {
    hiddenFiles?:  HiddenFileVulnerability[];
    ports?: PortScanResult[];
    technologies?: TechnologyInfo[];
    vulnerabilities?: Vulnerability[];
  };
  error?: string;
}

export interface ScannerModule {
  name: string;
  scan: (target: string) => Promise<any>;
}

// src/types/index.ts
export interface HiddenFileVulnerability {
  type: 'xss' | 'information_disclosure' | 'csrf' | 'sqli' | 'directory_traversal';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  path: string;
  status: number;
  evidence: string;
  recommendation?: string; // Added for better reporting
}