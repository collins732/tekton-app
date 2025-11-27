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
  type: 'xss' | 'sqli' | 'security-header' | 'info' | 'config' | 'auth' | 'access-control' | 'ssrf' | 'lfi' | 'rfi' | 'xxe' | 'command-injection' | 'auth-bypass' | 'sensitive-data' | 'idor';
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
    discoveredEndpoints?: string[]; // URLs discovered during crawl
  };
  error?: string;
}

export interface ScannerModule {
  name: string;
  scan: (target: string) => Promise<any>;
}

// Interface pour les fichiers sensibles/cachés exposés
export interface HiddenFileVulnerability {
  type: 'xss' | 'information_disclosure' | 'csrf' | 'sqli' | 'directory_traversal';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  path: string;
  status: number;
  evidence: string;
  recommendation?: string;
}
