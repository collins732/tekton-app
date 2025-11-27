'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import TestOption from '@/components/TestOption';
import LegalWarningModal from '@/components/LegalWarningModal';
import { ScanResult } from '../lib/types';

export default function ScanPage() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const terminalRef = useRef<HTMLDivElement>(null);

  // User authentication and data
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  // Legal warning modal
  const [showLegalWarning, setShowLegalWarning] = useState(false);
  const [hasAcceptedTerms, setHasAcceptedTerms] = useState(false);
  const [pendingScan, setPendingScan] = useState(false);

  // Check authentication on page load
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch('/api/auth/session');
        const data = await response.json();

        if (!data.authenticated || !data.user) {
          // Redirect to login if not authenticated
          router.push('/login');
          return;
        }

        setIsAuthenticated(true);
        setUser(data.user);
      } catch (error) {
        console.error('Auth check failed:', error);
        router.push('/login');
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, [router]);

  // Check if user has accepted terms in this session
  useEffect(() => {
    const termsAccepted = localStorage.getItem('tekton_terms_accepted');
    console.log('[DEBUG] Terms accepted from localStorage:', termsAccepted);
    if (termsAccepted === 'true') {
      setHasAcceptedTerms(true);
    } else {
      setHasAcceptedTerms(false);
    }
  }, []);

  // Test selection state
  const [selectedTests, setSelectedTests] = useState({
    portScan: true,
    xss: true,
    sqli: false,
    deepScan: false
  });

  const testOptions = [
    {
      id: 'portScan',
      name: 'PORT SCAN',
      description: 'Detect open ports and services',
      cost: 5,
      locked: false
    },
    {
      id: 'xss',
      name: 'XSS DETECTION',
      description: 'Find Cross-Site Scripting vulnerabilities',
      cost: 15,
      locked: false
    },
    {
      id: 'sqli',
      name: 'SQLI TESTING',
      description: 'Identify SQL injection points',
      cost: 20,
      locked: user?.plan === 'BASIC',
      lockReason: 'PRO ONLY'
    },
    {
      id: 'deepScan',
      name: 'DEEP SCAN',
      description: 'Comprehensive vulnerability analysis',
      cost: 100,
      locked: user?.plan !== 'EXPERT',
      lockReason: 'EXPERT ONLY'
    }
  ];

  const totalCost = testOptions.reduce((sum, test) => {
    return selectedTests[test.id as keyof typeof selectedTests] ? sum + test.cost : sum;
  }, 0);

  const hasInsufficientTokens = user ? totalCost > user.tokens : true;

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalOutput]);

  const addOutput = (text: string, type: 'info' | 'success' | 'error' | 'warning' = 'info') => {
    const colors = {
      info: '#e8e8e8',
      success: '#00ff00',
      error: '#ff0055',
      warning: '#8b5cf6',
    };
    setTerminalOutput(prev => [...prev, `<span style="color: ${colors[type]}">${text}</span>`]);
  };

  const handleAcceptTerms = () => {
    // Store acceptance in localStorage
    localStorage.setItem('tekton_terms_accepted', 'true');
    setHasAcceptedTerms(true);
    setShowLegalWarning(false);

    // If there was a pending scan, execute it now
    if (pendingScan) {
      setPendingScan(false);
      executeScan();
    }
  };

  const startScan = async () => {
    if (!url) {
      addOutput('[ERROR] Please enter a valid URL', 'error');
      return;
    }

    if (hasInsufficientTokens) {
      addOutput('[ERROR] Insufficient tokens. Please upgrade your plan or buy more tokens.', 'error');
      return;
    }

    // Check if user has accepted terms
    console.log('[DEBUG] hasAcceptedTerms:', hasAcceptedTerms);
    console.log('[DEBUG] showLegalWarning:', showLegalWarning);

    if (!hasAcceptedTerms) {
      console.log('[DEBUG] Showing legal warning modal...');
      setPendingScan(true);
      setShowLegalWarning(true);
      return;
    }

    executeScan();
  };

  const executeScan = async () => {
    setScanning(true);
    setScanResult(null);
    setTerminalOutput([]);

    addOutput('╔══════════════════════════════════════════════════════╗', 'warning');
    addOutput('║            TEKTON VULNERABILITY SCANNER              ║', 'warning');
    addOutput('╚══════════════════════════════════════════════════════╝', 'warning');
    addOutput('');
    addOutput(`[*] Target: ${url}`, 'info');
    addOutput(`[*] Cost: ${totalCost} tokens`, 'info');
    addOutput('[*] Initializing scan...', 'info');

    try {
      // Lancer le scan
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, cost: totalCost }),
      });

      const { scanId } = await response.json();
      addOutput(`[+] Scan ID: ${scanId}`, 'success');
      addOutput('[*] Scan started successfully', 'success');
      addOutput('');

      // Polling pour suivre la progression
      const interval = setInterval(async () => {
        const statusResponse = await fetch(`/api/scan/${scanId}`);
        const scan: ScanResult = await statusResponse.json();

        if (scan.currentStep) {
          addOutput(`[${scan.progress}%] ${scan.currentStep}`, 'warning');
        }

        if (scan.status === 'completed' || scan.status === 'failed') {
          clearInterval(interval);
          setScanning(false);
          setScanResult(scan);

          if (scan.status === 'completed') {
            addOutput('');
            addOutput('═══════════════════ SCAN COMPLETED ═══════════════════', 'success');
            displayResults(scan);
          } else {
            addOutput('');
            addOutput('[!] Scan failed: ' + scan.error, 'error');
          }
        }
      }, 2000);

    } catch (error) {
      addOutput('[!] Error: ' + (error as Error).message, 'error');
      setScanning(false);
    }
  };

  const displayResults = (scan: ScanResult) => {
    addOutput('');

    // Pages découvertes
    const discoveredEndpoints = scan.results.discoveredEndpoints || [];
    if (discoveredEndpoints.length > 0) {
      addOutput(`▼ CRAWLED PAGES (${discoveredEndpoints.length} discovered)`, 'warning');
      discoveredEndpoints.slice(0, 5).forEach((url: string, idx: number) => {
        addOutput(`  ├─ ${url}`, 'info');
      });
      if (discoveredEndpoints.length > 5) {
        addOutput(`  └─ ... and ${discoveredEndpoints.length - 5} more pages`, 'info');
      }
      addOutput('');
    }

    // Ports
    if (scan.results.ports && scan.results.ports.length > 0) {
      addOutput('▼ OPEN PORTS', 'warning');
      scan.results.ports.forEach(port => {
        addOutput(`  ├─ Port ${port.port} (${port.service})`, 'success');
      });
      addOutput('');
    }

    // Technologies
    if (scan.results.technologies && scan.results.technologies.length > 0) {
      addOutput('▼ TECHNOLOGIES DETECTED', 'warning');
      scan.results.technologies.forEach(tech => {
        const version = tech.version ? ` v${tech.version}` : '';
        addOutput(`  ├─ ${tech.name}${version} [${tech.category}]`, 'info');
      });
      addOutput('');
    }

    // Hidden Files
    if (scan.results.hiddenFiles && scan.results.hiddenFiles.length > 0) {
      addOutput('▼ SENSITIVE FILES FOUND', 'error');
      scan.results.hiddenFiles.forEach((file: any) => {
        addOutput(`  ├─ ${file.path} [${file.severity.toUpperCase()}]`, 'error');
      });
      addOutput('');
    }

    // Vulnérabilités
    if (scan.results.vulnerabilities && scan.results.vulnerabilities.length > 0) {
      addOutput('▼ VULNERABILITIES FOUND', 'error');
      addOutput('');
      scan.results.vulnerabilities.forEach((vuln, index) => {
        const severityColor = {
          critical: '#ff0055',
          high: '#ff6b6b',
          medium: '#ffd93d',
          low: '#a0d2db',
          info: '#e8e8e8',
        }[vuln.severity];

        addOutput(`  [${index + 1}] ${vuln.title}`, 'error');
        addOutput(`      Severity: <span style="color: ${severityColor}; font-weight: bold">${vuln.severity.toUpperCase()}</span>`, 'error');
        addOutput(`      Type: ${vuln.type.toUpperCase()}`, 'info');
        addOutput(`      Description: ${vuln.description}`, 'info');
        if (vuln.location) {
          addOutput(`      Location: ${vuln.location}`, 'info');
        }
        addOutput('');
      });
    } else {
      addOutput('[+] No vulnerabilities found!', 'success');
    }

    addOutput('═══════════════════════════════════════════════════════', 'success');
  };

  // Show loading state while checking authentication
  if (loading || !isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="terminal-border bg-black/90 backdrop-blur p-8 text-center">
          <div className="text-purple-400 text-4xl mb-4 animate-pulse">⚡</div>
          <div className="text-lg glow-purple">AUTHENTICATING...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">

        {/* Scan Configuration Section */}
        <div className="terminal-border bg-black/80 backdrop-blur p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold glow-purple">SELECT SCAN TYPES</h2>
            {hasAcceptedTerms && (
              <button
                onClick={() => {
                  localStorage.removeItem('tekton_terms_accepted');
                  setHasAcceptedTerms(false);
                  alert('Legal terms reset. You will see the warning modal on next scan.');
                }}
                className="text-xs px-3 py-1 bg-gray-800 hover:bg-gray-700 border border-gray-600 transition-all"
              >
                [Reset Legal Terms]
              </button>
            )}
          </div>

          {/* Test Options Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            {testOptions.map((test) => (
              <TestOption
                key={test.id}
                name={test.name}
                description={test.description}
                cost={test.cost}
                selected={selectedTests[test.id as keyof typeof selectedTests]}
                locked={test.locked}
                lockReason={test.lockReason}
                onToggle={() => {
                  if (!test.locked) {
                    setSelectedTests(prev => ({
                      ...prev,
                      [test.id]: !prev[test.id as keyof typeof selectedTests]
                    }));
                  }
                }}
              />
            ))}
          </div>

          {/* Total Cost Display */}
          <div className="terminal-border bg-purple-900/20 p-4 mb-4">
            <div className="flex items-center justify-between">
              <span className="text-lg font-bold">TOTAL COST:</span>
              <div className="flex items-center gap-2">
                <span className="text-3xl font-bold glow-purple">{totalCost}</span>
                <span className="text-purple-400 text-2xl">⚡</span>
                <span className="text-sm opacity-50">tokens</span>
              </div>
            </div>
          </div>

          {/* Insufficient Tokens Warning */}
          {hasInsufficientTokens && (
            <div className="terminal-border border-red-600 bg-red-900/20 p-4 mb-4 animate-pulse">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">⚠</span>
                  <div>
                    <div className="font-bold text-red-400">INSUFFICIENT TOKENS</div>
                    <div className="text-xs opacity-70">
                      You need {totalCost - (user?.tokens || 0)} more tokens to run this scan
                    </div>
                  </div>
                </div>
                <Link
                  href="/pricing"
                  className="px-4 py-2 bg-red-600 hover:bg-red-500 border-2 border-red-400 font-bold transition-all"
                >
                  [UPGRADE PLAN]
                </Link>
              </div>
            </div>
          )}
        </div>

        {/* URL Input Section */}
        <div className="terminal-border p-6 bg-black/50 backdrop-blur mb-6">
          <label className="block mb-2 text-sm glow-purple">
            {'> ENTER TARGET URL:'}
          </label>
          <div className="flex gap-4">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && !scanning && startScan()}
              placeholder="http://example.com"
              disabled={scanning}
              className="flex-1 bg-black border-2 border-purple-600 text-green-400 px-4 py-3
                       font-mono focus:outline-none focus:border-purple-400
                       disabled:opacity-50 disabled:cursor-not-allowed"
            />
            <button
              onClick={startScan}
              disabled={scanning || !url || hasInsufficientTokens}
              className="px-8 py-3 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-600
                       disabled:cursor-not-allowed border-2 border-purple-400
                       font-bold transition-all glow-purple"
            >
              {scanning ? '[SCANNING...]' : '[START SCAN]'}
            </button>
          </div>
        </div>

        {/* Terminal Output */}
        <div className="terminal-border bg-black/80 backdrop-blur">
          {/* Terminal Header */}
          <div className="bg-purple-900/30 px-4 py-2 border-b-2 border-purple-600 flex items-center justify-between">
            <span className="text-sm glow-purple">TERMINAL OUTPUT</span>
            <div className="flex gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
            </div>
          </div>

          {/* Terminal Content */}
          <div
            ref={terminalRef}
            className="p-6 h-96 overflow-y-auto font-mono text-sm leading-relaxed"
          >
            {terminalOutput.length === 0 ? (
              <div className="text-gray-500 flex flex-col items-center justify-center h-full">
                <span className="text-6xl mb-4">⚡</span>
                <span>Waiting for scan to start...</span>
                <span className="text-xs mt-2 opacity-50">Configure your scan and click [START SCAN]</span>
              </div>
            ) : (
              terminalOutput.map((line, index) => (
                <div
                  key={index}
                  dangerouslySetInnerHTML={{ __html: line }}
                  className="mb-1"
                />
              ))
            )}
            {scanning && (
              <span className="inline-block w-2 h-4 bg-purple-500 animate-pulse ml-1"></span>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 text-center text-xs opacity-50">
          <p>⚠ For educational purposes only. Do not scan websites without permission.</p>
        </div>
      </div>

      {/* Legal Warning Modal */}
      <LegalWarningModal
        isOpen={showLegalWarning}
        onAccept={handleAcceptTerms}
        onClose={() => {
          setShowLegalWarning(false);
          setPendingScan(false);
        }}
      />
    </div>
  );
}
