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
  type: 'xss' | 'sqli' | 'info' | 'config';
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
