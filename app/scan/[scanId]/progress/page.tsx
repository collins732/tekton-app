'use client';

import { useParams } from 'next/navigation';
import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';

interface Module {
  name: string;
  status: 'completed' | 'in_progress' | 'pending';
}

export default function ScanProgressPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const terminalRef = useRef<HTMLDivElement>(null);

  // Mock data
  const [progress, setProgress] = useState(35);
  const [currentStep, setCurrentStep] = useState('Scanning ports');
  const [timeRemaining, setTimeRemaining] = useState(120); // seconds
  const [logs, setLogs] = useState<string[]>([
    '[12:34:56] Initiating port scan...',
    '[12:34:57] Port 80: OPEN (HTTP)',
    '[12:34:58] Port 443: OPEN (HTTPS)',
    '[12:34:59] Port 22: OPEN (SSH)',
    '[12:35:00] Port 3306: CLOSED',
    '[12:35:01] Port scan completed',
    '[12:35:02] Testing for XSS vulnerabilities...',
  ]);

  const [modules, setModules] = useState<Module[]>([
    { name: 'Port Scanner', status: 'completed' },
    { name: 'XSS Detection', status: 'in_progress' },
    { name: 'SQLi Testing', status: 'pending' },
    { name: 'Tech Detection', status: 'pending' },
  ]);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  // Simulate progress
  useEffect(() => {
    const interval = setInterval(() => {
      setProgress(prev => Math.min(prev + 1, 100));
      setTimeRemaining(prev => Math.max(prev - 1, 0));

      // Add random log
      const newLogs = [
        '[12:35:03] Checking input field: username',
        '[12:35:04] Testing payload: <script>alert(1)</script>',
        '[12:35:05] No XSS vulnerability found in form',
        '[12:35:06] Analyzing response headers...',
      ];

      if (Math.random() > 0.7) {
        const randomLog = newLogs[Math.floor(Math.random() * newLogs.length)];
        setLogs(prev => [...prev, randomLog]);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="mb-8 text-center">
          <h1 className="text-4xl font-bold mb-4 glow-purple animate-pulse">
            [SCAN IN PROGRESS]
          </h1>
          <div className="text-2xl mb-2">example.com</div>
          <div className="inline-block bg-purple-600 px-4 py-1 text-sm font-bold animate-pulse">
            RUNNING
          </div>
        </div>

        {/* Global Progress Bar */}
        <div className="terminal-border bg-black/80 backdrop-blur p-6 mb-6">
          <div className="mb-4">
            <div className="flex justify-between items-center mb-2">
              <span className="text-lg font-bold glow-purple">{currentStep}<span className="animate-pulse">...</span></span>
              <span className="text-3xl font-bold glow-green">{progress}%</span>
            </div>
            <div className="h-4 bg-gray-900 terminal-border overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-purple-600 to-green-500 transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>

          {/* Time Remaining */}
          <div className="text-center text-sm opacity-70">
            Estimated time remaining: ~{formatTime(timeRemaining)}
          </div>
        </div>

        {/* Module Status */}
        <div className="terminal-border bg-black/80 backdrop-blur p-6 mb-6">
          <h2 className="text-xl font-bold mb-4 glow-purple">MODULE STATUS</h2>
          <div className="space-y-3">
            {modules.map((module, index) => (
              <div key={index} className="flex items-center gap-3 p-3 bg-black/50 border border-purple-600">
                {module.status === 'completed' && (
                  <span className="text-green-400 text-xl">✓</span>
                )}
                {module.status === 'in_progress' && (
                  <span className="text-purple-400 text-xl animate-spin">⟳</span>
                )}
                {module.status === 'pending' && (
                  <span className="text-gray-600 text-xl">⋯</span>
                )}

                <span className={`flex-1 font-bold ${
                  module.status === 'completed' ? 'text-green-400' :
                  module.status === 'in_progress' ? 'text-purple-400' :
                  'text-gray-600'
                }`}>
                  {module.name}
                </span>

                <span className={`text-xs font-bold px-3 py-1 ${
                  module.status === 'completed' ? 'bg-green-600' :
                  module.status === 'in_progress' ? 'bg-purple-600 animate-pulse' :
                  'bg-gray-700'
                }`}>
                  [{module.status.toUpperCase().replace('_', ' ')}]
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Terminal Log */}
        <div className="terminal-border bg-black/80 backdrop-blur mb-6">
          <div className="bg-purple-900/30 px-4 py-2 border-b-2 border-purple-600 flex items-center justify-between">
            <span className="text-sm glow-purple">REAL-TIME LOG</span>
            <div className="flex gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
            </div>
          </div>

          <div
            ref={terminalRef}
            className="p-6 h-80 overflow-y-auto font-mono text-sm leading-relaxed"
          >
            {logs.map((log, index) => {
              const isVuln = log.toLowerCase().includes('vulnerability') || log.toLowerCase().includes('found');
              const isError = log.toLowerCase().includes('error') || log.toLowerCase().includes('failed');
              const isSuccess = log.toLowerCase().includes('completed') || log.toLowerCase().includes('success');

              return (
                <div
                  key={index}
                  className={`mb-1 ${
                    isVuln ? 'text-red-400 font-bold' :
                    isError ? 'text-red-400' :
                    isSuccess ? 'text-green-400' :
                    'text-gray-300'
                  }`}
                >
                  {log}
                </div>
              );
            })}
            <span className="inline-block w-2 h-4 bg-purple-500 animate-pulse ml-1"></span>
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-center gap-4">
          <button
            onClick={() => {
              if (confirm('Are you sure you want to cancel this scan?')) {
                console.log('Scan cancelled');
              }
            }}
            className="px-6 py-3 bg-red-600 hover:bg-red-500 border-2 border-red-400 font-bold transition-all"
          >
            [CANCEL SCAN]
          </button>
          <Link
            href="/dashboard"
            className="px-6 py-3 bg-black hover:bg-gray-900 border-2 border-purple-400 font-bold transition-all"
          >
            [BACK TO DASHBOARD]
          </Link>
        </div>
      </div>
    </div>
  );
}
