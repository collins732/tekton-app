'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import LegalWarningModal from '@/components/LegalWarningModal';
import { ScanResult } from '../lib/types';

export default function ScanPage() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const terminalRef = useRef<HTMLDivElement>(null);
  const [currentStep, setCurrentStep] = useState('');
  const [progress, setProgress] = useState(0);

  // User authentication and data
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  // Legal warning modal
  const [showLegalWarning, setShowLegalWarning] = useState(false);
  const [hasAcceptedTerms, setHasAcceptedTerms] = useState(false);
  const [pendingScan, setPendingScan] = useState(false);

  // Error state
  const [errorMessage, setErrorMessage] = useState('');

  // Check authentication on page load
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch('/api/auth/session');
        const data = await response.json();

        if (!data.authenticated || !data.user) {
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

  // Check if user has accepted terms
  useEffect(() => {
    const termsAccepted = localStorage.getItem('tekton_terms_accepted');
    if (termsAccepted === 'true') {
      setHasAcceptedTerms(true);
    }
  }, []);

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
    localStorage.setItem('tekton_terms_accepted', 'true');
    setHasAcceptedTerms(true);
    setShowLegalWarning(false);

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

    if (!hasAcceptedTerms) {
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
    setCurrentStep('Initializing scan...');
    setProgress(0);
    setErrorMessage('');

    addOutput('╔══════════════════════════════════════════════════════╗', 'warning');
    addOutput('║            TEKTON VULNERABILITY SCANNER              ║', 'warning');
    addOutput('╚══════════════════════════════════════════════════════╝', 'warning');
    addOutput('');
    addOutput(`[*] Target: ${url}`, 'info');
    addOutput('[*] Initializing scan...', 'info');

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const error = await response.json();
        if (response.status === 402) {
          addOutput('[!] INSUFFICIENT TOKENS', 'error');
          addOutput(`[!] Required: 40 tokens | Available: ${user?.tokens || 0} tokens`, 'error');
          addOutput('[!] Please upgrade your plan to continue scanning', 'error');
          setScanning(false);
          setCurrentStep('');
          return;
        }
        throw new Error(error.message || 'Failed to start scan');
      }

      const data = await response.json();
      const scanId = data.scanId;

      if (!scanId) {
        throw new Error('No scan ID received');
      }

      addOutput(`[+] Scan ID: ${scanId}`, 'success');
      addOutput('[*] Scan started successfully', 'success');
      addOutput('');

      // Track last step to avoid duplicates
      let lastStep = '';
      let lastProgress = 0;

      // Polling for progress
      const interval = setInterval(async () => {
        try {
          const statusResponse = await fetch(`/api/scan/${scanId}`);
          if (!statusResponse.ok) {
            clearInterval(interval);
            setScanning(false);
            addOutput('[!] Error fetching scan status', 'error');
            setCurrentStep('');
            return;
          }

          const scan: ScanResult = await statusResponse.json();

          // Update progress
          if (scan.currentStep) {
            setCurrentStep(scan.currentStep);
            setProgress(scan.progress);
          }

          // Only add output if step changed or progress increased significantly
          if (scan.currentStep && (scan.currentStep !== lastStep || scan.progress >= lastProgress + 10)) {
            addOutput(`[${scan.progress}%] ${scan.currentStep}`, 'warning');
            lastStep = scan.currentStep;
            lastProgress = scan.progress;
          }

          if (scan.status === 'completed' || scan.status === 'failed') {
            clearInterval(interval);
            setScanning(false);
            setScanResult(scan);
            setCurrentStep('');
            setProgress(100);

            if (scan.status === 'completed') {
              addOutput('');
              addOutput('═══════════════════ SCAN COMPLETED ═══════════════════', 'success');
              displayResults(scan);
            } else {
              addOutput('');
              addOutput('[!] Scan failed: ' + scan.error, 'error');
            }
          }
        } catch (err) {
          clearInterval(interval);
          setScanning(false);
          addOutput('[!] Error during scan', 'error');
          setCurrentStep('');
        }
      }, 2000);

    } catch (error) {
      setScanning(false);
      addOutput('[!] Error: ' + (error as Error).message, 'error');
      setCurrentStep('');
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
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-5xl md:text-6xl font-bold mb-4 glow-purple">
            [VULNERABILITY SCANNER]
          </h1>
          <p className="text-xl opacity-70">
            Comprehensive security analysis for web applications
          </p>
        </div>

        {/* URL Input Section */}
        <div className="terminal-border p-6 bg-black/50 backdrop-blur mb-6">
          <div className="flex justify-between items-center mb-2">
            <label className="text-sm glow-purple">
              {'> ENTER TARGET URL:'}
            </label>
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
              disabled={scanning || !url}
              className="px-8 py-3 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-600
                       disabled:cursor-not-allowed border-2 border-purple-400
                       font-bold transition-all glow-purple"
            >
              {scanning ? '[SCANNING...]' : '[START SCAN]'}
            </button>
          </div>

          {/* Example URLs */}
          <div className="mt-4 flex items-center gap-4 text-sm">
            <span className="opacity-50">Test targets:</span>
            {['http://testphp.vulnweb.com', 'http://example.com'].map((exampleUrl) => (
              <button
                key={exampleUrl}
                onClick={() => setUrl(exampleUrl)}
                className="text-purple-400 hover:text-purple-300 transition-colors font-mono"
              >
                {exampleUrl}
              </button>
            ))}
          </div>
        </div>

        {/* Scanning Progress - Keep this as is since user likes it */}
        <AnimatePresence>
          {scanning && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="mb-12"
            >
              <div className="terminal-border bg-black/80 backdrop-blur p-8">
                <div className="space-y-6">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-lg font-bold glow-purple">SCANNING PROGRESS</span>
                      <span className="text-purple-400 font-bold text-2xl">{progress}%</span>
                    </div>
                    <div className="w-full bg-gray-900 rounded h-4 overflow-hidden border border-purple-600">
                      <motion.div
                        className="h-full bg-gradient-to-r from-purple-600 to-pink-600"
                        initial={{ width: 0 }}
                        animate={{ width: `${progress}%` }}
                        transition={{ duration: 0.5 }}
                      />
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 border-4 border-purple-600 border-t-transparent rounded-full animate-spin"></div>
                    <p className="text-purple-400 font-mono">{currentStep}</p>
                  </div>

                  {/* Live scan stats */}
                  <div className="grid grid-cols-3 gap-4 pt-4 border-t border-purple-600">
                    <div className="text-center">
                      <div className="text-3xl font-bold text-purple-400">
                        {Math.floor(progress / 25)}
                      </div>
                      <div className="text-xs opacity-50">Modules Complete</div>
                    </div>
                    <div className="text-center">
                      <div className="text-3xl font-bold text-pink-400">
                        {Math.floor(progress * 1.2)}
                      </div>
                      <div className="text-xs opacity-50">Checks Performed</div>
                    </div>
                    <div className="text-center">
                      <div className="text-3xl font-bold text-green-400">
                        {Math.floor(progress / 10)}s
                      </div>
                      <div className="text-xs opacity-50">Time Elapsed</div>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

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
                <span className="text-6xl mb-4 animate-pulse">⚡</span>
                <span>Waiting for scan to start...</span>
                <span className="text-xs mt-2 opacity-50">Enter a URL and click [START SCAN]</span>
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

        {/* Action Buttons */}
        {scanResult && scanResult.status === 'completed' && (
          <div className="mt-8 flex items-center justify-center gap-4">
            <button
              onClick={() => {
                setScanResult(null);
                setTerminalOutput([]);
                setUrl('');
              }}
              className="px-6 py-3 bg-gray-800 hover:bg-gray-700 border-2 border-gray-600
                       font-bold transition-all"
            >
              [NEW SCAN]
            </button>
            <Link
              href="/pricing"
              className="px-6 py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400
                       font-bold transition-all glow-purple"
            >
              [UPGRADE FOR MORE SCANS]
            </Link>
          </div>
        )}

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