'use client';

import { useParams, useRouter } from 'next/navigation';
import { useState, useEffect } from 'react';
import Link from 'next/link';

export default function ScanResultsPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.scanId as string;

  const [openAccordions, setOpenAccordions] = useState<string[]>(['ports']);
  const [scan, setScan] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // Load scan data from API
  useEffect(() => {
    const loadScan = async () => {
      try {
        const response = await fetch(`/api/scan/${scanId}`);
        if (response.ok) {
          const data = await response.json();
          setScan(data);
        } else {
          alert('Scan not found');
          router.push('/dashboard');
        }
      } catch (error) {
        console.error('Failed to load scan:', error);
      } finally {
        setLoading(false);
      }
    };

    loadScan();

    // Poll for updates if scan is running
    const interval = setInterval(async () => {
      if (scan?.status === 'running' || scan?.status === 'pending') {
        const response = await fetch(`/api/scan/${scanId}`);
        if (response.ok) {
          const data = await response.json();
          setScan(data);
        }
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId, router, scan?.status]);

  const toggleAccordion = (id: string) => {
    setOpenAccordions(prev =>
      prev.includes(id) ? prev.filter(item => item !== id) : [...prev, id]
    );
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="terminal-border bg-black/90 backdrop-blur p-8 text-center">
          <div className="text-purple-400 text-4xl mb-4 animate-pulse">[*]</div>
          <div className="text-lg glow-purple">LOADING SCAN...</div>
        </div>
      </div>
    );
  }

  if (!scan) return null;

  // Parse results if string
  const results = scan.results ? (typeof scan.results === 'string' ? JSON.parse(scan.results) : scan.results) : null;

  // Calculate vulnerability counts
  let vulnCounts = { high: 0, medium: 0, low: 0 };
  if (results?.vulnerabilities) {
    results.vulnerabilities.forEach((v: any) => {
      const sev = (v.severity || '').toLowerCase();
      if (sev === 'high' || sev === 'critical') vulnCounts.high++;
      else if (sev === 'medium') vulnCounts.medium++;
      else vulnCounts.low++;
    });
  }

  // Calculate security score (100 - penalty for vulns)
  const securityScore = Math.max(0, 100 - (vulnCounts.high * 20) - (vulnCounts.medium * 10) - (vulnCounts.low * 5));

  // Determine risk level
  const riskLevel = vulnCounts.high > 0 ? 'high' : vulnCounts.medium > 0 ? 'medium' : vulnCounts.low > 0 ? 'low' : 'secure';

  // Format date
  const formattedDate = new Date(scan.started_at).toLocaleString();

  // Calculate duration if completed
  const duration = scan.completed_at ?
    `${Math.round((scan.completed_at - scan.started_at) / 1000)}s` :
    'In progress';

  const scanData = {
    url: scan.target,
    date: formattedDate,
    duration,
    status: scan.status,
    securityScore,
    riskLevel,
    vulnerabilities: vulnCounts,
  };

  const riskConfig = {
    critical: { color: 'bg-red-600', text: 'CRITICAL' },
    high: { color: 'bg-orange-600', text: 'HIGH' },
    medium: { color: 'bg-yellow-600', text: 'MEDIUM' },
    low: { color: 'bg-blue-600', text: 'LOW' },
    secure: { color: 'bg-green-600', text: 'SECURE' },
  };

  const currentRisk = riskConfig[scanData.riskLevel as keyof typeof riskConfig];

  const copyToClipboard = () => {
    navigator.clipboard.writeText(window.location.href);
    alert('Link copied to clipboard!');
  };

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header Section */}
        <div className="terminal-border bg-black/80 backdrop-blur p-8 mb-8">
          <div className="text-center mb-6">
            <h1 className="text-4xl font-bold mb-4 glow-purple">{scanData.url}</h1>
            <div className="flex flex-wrap justify-center gap-4 text-sm">
              <span className="bg-green-600 px-3 py-1 font-bold">[{scanData.status.toUpperCase()}] ✓</span>
              <span className="opacity-70">{scanData.date}</span>
              <span className="opacity-70">Duration: {scanData.duration}</span>
            </div>
          </div>

          {/* Security Score */}
          <div className="flex flex-col md:flex-row items-center justify-center gap-8">
            <div className="text-center">
              <div className="text-6xl font-bold mb-2">
                <span className={
                  scanData.securityScore >= 70 ? 'text-green-400' :
                  scanData.securityScore >= 40 ? 'text-yellow-400' :
                  'text-red-400'
                }>{scanData.securityScore}</span>
                <span className="text-3xl opacity-50">/100</span>
              </div>
              <div className="text-sm opacity-50">SECURITY SCORE</div>
            </div>

            <div className="w-px h-20 bg-purple-600 hidden md:block"></div>

            <div className="text-center">
              <div className={`${currentRisk.color} px-6 py-3 text-2xl font-bold mb-2`}>
                [{currentRisk.text}]
              </div>
              <div className="text-sm opacity-50">RISK LEVEL</div>
            </div>
          </div>
        </div>

        {/* Vulnerabilities Summary */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="terminal-border bg-black/80 backdrop-blur p-6 text-center">
            <div className="text-5xl font-bold text-red-400 mb-2">{scanData.vulnerabilities.high}</div>
            <div className="text-sm opacity-50">HIGH SEVERITY</div>
          </div>
          <div className="terminal-border bg-black/80 backdrop-blur p-6 text-center">
            <div className="text-5xl font-bold text-yellow-400 mb-2">{scanData.vulnerabilities.medium}</div>
            <div className="text-sm opacity-50">MEDIUM SEVERITY</div>
          </div>
          <div className="terminal-border bg-black/80 backdrop-blur p-6 text-center">
            <div className="text-5xl font-bold text-blue-400 mb-2">{scanData.vulnerabilities.low}</div>
            <div className="text-sm opacity-50">LOW SEVERITY</div>
          </div>
        </div>

        {/* Distribution Bar */}
        <div className="terminal-border bg-black/80 backdrop-blur p-4 mb-8">
          <div className="text-sm opacity-50 mb-2">VULNERABILITY DISTRIBUTION</div>
          <div className="h-8 flex overflow-hidden terminal-border">
            <div
              className="bg-red-600 flex items-center justify-center text-xs font-bold"
              style={{ width: `${(scanData.vulnerabilities.high / 10) * 100}%` }}
            >
              {scanData.vulnerabilities.high > 0 && scanData.vulnerabilities.high}
            </div>
            <div
              className="bg-yellow-600 flex items-center justify-center text-xs font-bold"
              style={{ width: `${(scanData.vulnerabilities.medium / 10) * 100}%` }}
            >
              {scanData.vulnerabilities.medium > 0 && scanData.vulnerabilities.medium}
            </div>
            <div
              className="bg-blue-600 flex items-center justify-center text-xs font-bold"
              style={{ width: `${(scanData.vulnerabilities.low / 10) * 100}%` }}
            >
              {scanData.vulnerabilities.low > 0 && scanData.vulnerabilities.low}
            </div>
          </div>
        </div>

        {/* Results by Module - Accordions */}
        <div className="space-y-4 mb-8">
          {/* Port Scanner */}
          <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
            <button
              onClick={() => toggleAccordion('ports')}
              className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
            >
              <span className="text-xl font-bold glow-purple">[PORT SCANNER]</span>
              <span className="text-2xl">{openAccordions.includes('ports') ? '▼' : '▶'}</span>
            </button>
            {openAccordions.includes('ports') && (
              <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                <div className="space-y-3">
                  <div className="flex items-center gap-4 p-3 bg-green-900/20 border border-green-600">
                    <span className="text-green-400 font-bold">Port 80</span>
                    <span className="text-sm opacity-70">(HTTP)</span>
                    <span className="text-green-400 ml-auto">OPEN</span>
                  </div>
                  <div className="flex items-center gap-4 p-3 bg-green-900/20 border border-green-600">
                    <span className="text-green-400 font-bold">Port 443</span>
                    <span className="text-sm opacity-70">(HTTPS)</span>
                    <span className="text-green-400 ml-auto">OPEN</span>
                  </div>
                  <div className="flex items-center gap-4 p-3 bg-green-900/20 border border-green-600">
                    <span className="text-green-400 font-bold">Port 22</span>
                    <span className="text-sm opacity-70">(SSH)</span>
                    <span className="text-green-400 ml-auto">OPEN</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* XSS Detection */}
          <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
            <button
              onClick={() => toggleAccordion('xss')}
              className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
            >
              <span className="text-xl font-bold glow-purple">[XSS DETECTION]</span>
              <span className="text-2xl">{openAccordions.includes('xss') ? '▼' : '▶'}</span>
            </button>
            {openAccordions.includes('xss') && (
              <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                <div className="space-y-6">
                  {/* Vulnerability 1 */}
                  <div className="terminal-border border-red-600 bg-red-900/20 p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h4 className="text-lg font-bold text-red-400 mb-1">Reflected XSS in search parameter</h4>
                        <span className="bg-red-600 px-2 py-1 text-xs font-bold">HIGH SEVERITY</span>
                      </div>
                    </div>
                    <p className="text-sm opacity-70 mb-3">
                      User input from 'search' parameter is directly reflected in the page without proper sanitization.
                    </p>
                    <div className="mb-3">
                      <div className="text-xs opacity-50 mb-1">LOCATION:</div>
                      <code className="text-xs bg-black p-2 block">{'/search?q=<script>alert(1)</script>'}</code>
                    </div>
                    <div className="mb-3">
                      <div className="text-xs opacity-50 mb-1">VULNERABLE CODE:</div>
                      <code className="text-xs bg-black p-2 block font-mono">
                        {'<div>{query}</div>'}
                      </code>
                    </div>
                    <div>
                      <div className="text-xs opacity-50 mb-1">RECOMMENDATION:</div>
                      <p className="text-xs opacity-70">
                        Implement proper output encoding using DOMPurify or similar library. Never insert user input directly into HTML.
                      </p>
                    </div>
                  </div>

                  {/* Vulnerability 2 */}
                  <div className="terminal-border border-yellow-600 bg-yellow-900/20 p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h4 className="text-lg font-bold text-yellow-400 mb-1">DOM-based XSS in URL fragment</h4>
                        <span className="bg-yellow-600 px-2 py-1 text-xs font-bold text-black">MEDIUM SEVERITY</span>
                      </div>
                    </div>
                    <p className="text-sm opacity-70 mb-3">
                      JavaScript code uses window.location.hash without validation.
                    </p>
                    <div>
                      <div className="text-xs opacity-50 mb-1">RECOMMENDATION:</div>
                      <p className="text-xs opacity-70">
                        Validate and sanitize URL fragments before using them in DOM manipulation.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* SQLi Testing */}
          <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
            <button
              onClick={() => toggleAccordion('sqli')}
              className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
            >
              <span className="text-xl font-bold glow-purple">[SQLI TESTING]</span>
              <span className="text-2xl">{openAccordions.includes('sqli') ? '▼' : '▶'}</span>
            </button>
            {openAccordions.includes('sqli') && (
              <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                <div className="terminal-border border-red-600 bg-red-900/20 p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <h4 className="text-lg font-bold text-red-400 mb-1">SQL Injection in login form</h4>
                      <span className="bg-red-600 px-2 py-1 text-xs font-bold">CRITICAL SEVERITY</span>
                    </div>
                  </div>
                  <p className="text-sm opacity-70 mb-3">
                    Authentication bypass possible through SQL injection in username field.
                  </p>
                  <div className="mb-3">
                    <div className="text-xs opacity-50 mb-1">PAYLOAD USED:</div>
                    <code className="text-xs bg-black p-2 block">' OR '1'='1</code>
                  </div>
                  <div>
                    <div className="text-xs opacity-50 mb-1">RECOMMENDATION:</div>
                    <p className="text-xs opacity-70">
                      Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Tech Detection */}
          <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
            <button
              onClick={() => toggleAccordion('tech')}
              className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
            >
              <span className="text-xl font-bold glow-purple">[TECH DETECTION]</span>
              <span className="text-2xl">{openAccordions.includes('tech') ? '▼' : '▶'}</span>
            </button>
            {openAccordions.includes('tech') && (
              <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-3 bg-purple-900/20 border border-purple-600">
                    <div className="text-xs opacity-50 mb-1">SERVER</div>
                    <div className="font-bold">Apache 2.4.41</div>
                  </div>
                  <div className="p-3 bg-purple-900/20 border border-purple-600">
                    <div className="text-xs opacity-50 mb-1">FRAMEWORK</div>
                    <div className="font-bold">Express.js 4.18.2</div>
                  </div>
                  <div className="p-3 bg-purple-900/20 border border-purple-600">
                    <div className="text-xs opacity-50 mb-1">LANGUAGE</div>
                    <div className="font-bold">Node.js 18.x</div>
                  </div>
                  <div className="p-3 bg-purple-900/20 border border-purple-600">
                    <div className="text-xs opacity-50 mb-1">CMS</div>
                    <div className="font-bold">WordPress 6.3</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Recommendations */}
        <div className="terminal-border bg-purple-900/20 backdrop-blur p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4 glow-purple">[PRIORITY RECOMMENDATIONS]</h2>
          <ol className="space-y-4">
            <li className="flex gap-4">
              <span className="text-2xl font-bold text-red-400">1.</span>
              <div>
                <div className="font-bold mb-1">Fix SQL Injection vulnerability immediately</div>
                <p className="text-sm opacity-70 mb-2">
                  This is a critical vulnerability that allows authentication bypass and database access.
                </p>
                <a
                  href="https://owasp.org/www-community/attacks/SQL_Injection"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-purple-400 text-xs hover:underline"
                >
                  → OWASP SQL Injection Guide
                </a>
              </div>
            </li>
            <li className="flex gap-4">
              <span className="text-2xl font-bold text-red-400">2.</span>
              <div>
                <div className="font-bold mb-1">Implement XSS protection</div>
                <p className="text-sm opacity-70 mb-2">
                  Add Content Security Policy headers and sanitize all user inputs.
                </p>
                <a
                  href="https://owasp.org/www-community/attacks/xss/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-purple-400 text-xs hover:underline"
                >
                  → OWASP XSS Prevention Guide
                </a>
              </div>
            </li>
            <li className="flex gap-4">
              <span className="text-2xl font-bold text-yellow-400">3.</span>
              <div>
                <div className="font-bold mb-1">Update server software</div>
                <p className="text-sm opacity-70 mb-2">
                  Some detected technologies have known vulnerabilities. Update to latest stable versions.
                </p>
                <a
                  href="https://owasp.org/www-project-top-ten/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-purple-400 text-xs hover:underline"
                >
                  → OWASP Top 10
                </a>
              </div>
            </li>
          </ol>
        </div>

        {/* Actions */}
        <div className="flex flex-wrap justify-center gap-4">
          <button
            onClick={() => console.log('TODO: Export PDF')}
            className="px-6 py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
          >
            [EXPORT PDF]
          </button>
          <Link
            href={`/scan?url=${scanData.url}`}
            className="px-6 py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
          >
            [RE-SCAN]
          </Link>
          <button
            onClick={copyToClipboard}
            className="px-6 py-3 bg-black hover:bg-gray-900 border-2 border-purple-400 font-bold transition-all"
          >
            [SHARE LINK]
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
