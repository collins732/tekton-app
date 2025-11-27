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

  // Get real data from results
  const ports = results?.ports || [];
  const technologies = results?.technologies || [];
  const vulnerabilities = results?.vulnerabilities || [];
  const hiddenFiles = results?.hiddenFiles || [];
  const discoveredEndpoints = results?.discoveredEndpoints || [];

  // Calculate vulnerability counts by severity
  let vulnCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  vulnerabilities.forEach((v: any) => {
    const sev = (v.severity || '').toLowerCase();
    if (sev === 'critical') vulnCounts.critical++;
    else if (sev === 'high') vulnCounts.high++;
    else if (sev === 'medium') vulnCounts.medium++;
    else if (sev === 'low') vulnCounts.low++;
    else vulnCounts.info++;
  });

  // Group vulnerabilities by type
  const vulnsByType: Record<string, any[]> = {};
  vulnerabilities.forEach((v: any) => {
    const type = (v.type || 'other').toLowerCase();
    if (!vulnsByType[type]) vulnsByType[type] = [];
    vulnsByType[type].push(v);
  });

  // Calculate security score (100 - penalty for vulns)
  const totalHighSeverity = vulnCounts.critical + vulnCounts.high;
  const securityScore = Math.max(0, 100 - (vulnCounts.critical * 25) - (vulnCounts.high * 15) - (vulnCounts.medium * 8) - (vulnCounts.low * 3));

  // Determine risk level
  const riskLevel = vulnCounts.critical > 0 ? 'critical' :
                    vulnCounts.high > 0 ? 'high' :
                    vulnCounts.medium > 0 ? 'medium' :
                    vulnCounts.low > 0 ? 'low' : 'secure';

  // Format date
  const formattedDate = new Date(scan.started_at).toLocaleString();

  // Calculate duration if completed
  const duration = scan.completed_at ?
    `${Math.round((scan.completed_at - scan.started_at) / 1000)}s` :
    'In progress';

  const riskConfig = {
    critical: { color: 'bg-red-600', text: 'CRITICAL' },
    high: { color: 'bg-orange-600', text: 'HIGH' },
    medium: { color: 'bg-yellow-600', text: 'MEDIUM' },
    low: { color: 'bg-blue-600', text: 'LOW' },
    secure: { color: 'bg-green-600', text: 'SECURE' },
  };

  const currentRisk = riskConfig[riskLevel as keyof typeof riskConfig];

  const severityColors: Record<string, { bg: string; text: string; border: string }> = {
    critical: { bg: 'bg-red-900/30', text: 'text-red-400', border: 'border-red-600' },
    high: { bg: 'bg-orange-900/30', text: 'text-orange-400', border: 'border-orange-600' },
    medium: { bg: 'bg-yellow-900/30', text: 'text-yellow-400', border: 'border-yellow-600' },
    low: { bg: 'bg-blue-900/30', text: 'text-blue-400', border: 'border-blue-600' },
    info: { bg: 'bg-gray-900/30', text: 'text-gray-400', border: 'border-gray-600' },
  };

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
            <h1 className="text-4xl font-bold mb-4 glow-purple">{scan.target}</h1>
            <div className="flex flex-wrap justify-center gap-4 text-sm">
              <span className={`px-3 py-1 font-bold ${scan.status === 'completed' ? 'bg-green-600' : scan.status === 'failed' ? 'bg-red-600' : 'bg-yellow-600'}`}>
                [{scan.status.toUpperCase()}] {scan.status === 'completed' ? '✓' : scan.status === 'failed' ? '✗' : '...'}
              </span>
              <span className="opacity-70">{formattedDate}</span>
              <span className="opacity-70">Duration: {duration}</span>
            </div>
          </div>

          {/* Security Score */}
          <div className="flex flex-col md:flex-row items-center justify-center gap-8">
            <div className="text-center">
              <div className="text-6xl font-bold mb-2">
                <span className={
                  securityScore >= 70 ? 'text-green-400' :
                  securityScore >= 40 ? 'text-yellow-400' :
                  'text-red-400'
                }>{securityScore}</span>
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
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <div className="terminal-border bg-black/80 backdrop-blur p-4 text-center">
            <div className="text-4xl font-bold text-red-400 mb-1">{vulnCounts.critical}</div>
            <div className="text-xs opacity-50">CRITICAL</div>
          </div>
          <div className="terminal-border bg-black/80 backdrop-blur p-4 text-center">
            <div className="text-4xl font-bold text-orange-400 mb-1">{vulnCounts.high}</div>
            <div className="text-xs opacity-50">HIGH</div>
          </div>
          <div className="terminal-border bg-black/80 backdrop-blur p-4 text-center">
            <div className="text-4xl font-bold text-yellow-400 mb-1">{vulnCounts.medium}</div>
            <div className="text-xs opacity-50">MEDIUM</div>
          </div>
          <div className="terminal-border bg-black/80 backdrop-blur p-4 text-center">
            <div className="text-4xl font-bold text-blue-400 mb-1">{vulnCounts.low}</div>
            <div className="text-xs opacity-50">LOW</div>
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
              <span className="text-xl font-bold glow-purple">[PORT SCANNER] ({ports.length} open)</span>
              <span className="text-2xl">{openAccordions.includes('ports') ? '▼' : '▶'}</span>
            </button>
            {openAccordions.includes('ports') && (
              <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                {ports.length > 0 ? (
                  <div className="space-y-3">
                    {ports.map((port: any, idx: number) => (
                      <div key={idx} className="flex items-center gap-4 p-3 bg-green-900/20 border border-green-600">
                        <span className="text-green-400 font-bold">Port {port.port}</span>
                        <span className="text-sm opacity-70">({port.service || 'Unknown'})</span>
                        <span className="text-green-400 ml-auto">OPEN</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center text-sm opacity-50 py-4">No open ports detected</div>
                )}
              </div>
            )}
          </div>

          {/* Technologies */}
          <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
            <button
              onClick={() => toggleAccordion('tech')}
              className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
            >
              <span className="text-xl font-bold glow-purple">[TECH DETECTION] ({technologies.length} found)</span>
              <span className="text-2xl">{openAccordions.includes('tech') ? '▼' : '▶'}</span>
            </button>
            {openAccordions.includes('tech') && (
              <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                {technologies.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {technologies.map((tech: any, idx: number) => (
                      <div key={idx} className="p-3 bg-purple-900/20 border border-purple-600">
                        <div className="text-xs opacity-50 mb-1 uppercase">{tech.category || 'Technology'}</div>
                        <div className="font-bold">{tech.name}{tech.version ? ` ${tech.version}` : ''}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center text-sm opacity-50 py-4">No technologies detected</div>
                )}
              </div>
            )}
          </div>

          {/* Discovered Endpoints */}
          {discoveredEndpoints.length > 0 && (
            <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
              <button
                onClick={() => toggleAccordion('endpoints')}
                className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
              >
                <span className="text-xl font-bold glow-purple">[CRAWLED PAGES] ({discoveredEndpoints.length} discovered)</span>
                <span className="text-2xl">{openAccordions.includes('endpoints') ? '▼' : '▶'}</span>
              </button>
              {openAccordions.includes('endpoints') && (
                <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                  <p className="text-sm opacity-70 mb-4">
                    The scanner automatically crawled the website and discovered these pages for testing:
                  </p>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {discoveredEndpoints.map((url: string, idx: number) => (
                      <div key={idx} className="flex items-center gap-2 p-2 bg-black/50 border border-purple-600/30 text-sm">
                        <span className="text-purple-400">{idx + 1}.</span>
                        <a
                          href={url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-400 hover:underline truncate flex-1"
                        >
                          {url}
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Security Headers Vulnerabilities */}
          {vulnsByType['security-header'] && vulnsByType['security-header'].length > 0 && (
            <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
              <button
                onClick={() => toggleAccordion('headers')}
                className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
              >
                <span className="text-xl font-bold glow-purple">[SECURITY HEADERS] ({vulnsByType['security-header'].length} issues)</span>
                <span className="text-2xl">{openAccordions.includes('headers') ? '▼' : '▶'}</span>
              </button>
              {openAccordions.includes('headers') && (
                <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                  <div className="space-y-4">
                    {vulnsByType['security-header'].map((vuln: any, idx: number) => {
                      const sev = (vuln.severity || 'info').toLowerCase();
                      const colors = severityColors[sev] || severityColors.info;
                      return (
                        <div key={idx} className={`terminal-border ${colors.border} ${colors.bg} p-4`}>
                          <div className="flex items-start justify-between mb-3">
                            <div>
                              <h4 className={`text-lg font-bold ${colors.text} mb-1`}>{vuln.title}</h4>
                              <span className={`${colors.bg} border ${colors.border} px-2 py-1 text-xs font-bold`}>
                                {(vuln.severity || 'INFO').toUpperCase()} SEVERITY
                              </span>
                            </div>
                          </div>
                          <p className="text-sm opacity-70 mb-3">{vuln.description}</p>
                          {vuln.location && (
                            <div className="mb-2">
                              <div className="text-xs opacity-50 mb-1">LOCATION:</div>
                              <code className="text-xs bg-black p-2 block break-all">{vuln.location}</code>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* XSS Vulnerabilities */}
          {vulnsByType['xss'] && vulnsByType['xss'].length > 0 && (
            <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
              <button
                onClick={() => toggleAccordion('xss')}
                className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
              >
                <span className="text-xl font-bold glow-purple">[XSS DETECTION] ({vulnsByType['xss'].length} found)</span>
                <span className="text-2xl">{openAccordions.includes('xss') ? '▼' : '▶'}</span>
              </button>
              {openAccordions.includes('xss') && (
                <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                  <div className="space-y-4">
                    {vulnsByType['xss'].map((vuln: any, idx: number) => {
                      const sev = (vuln.severity || 'high').toLowerCase();
                      const colors = severityColors[sev] || severityColors.high;
                      return (
                        <div key={idx} className={`terminal-border ${colors.border} ${colors.bg} p-4`}>
                          <div className="flex items-start justify-between mb-3">
                            <div>
                              <h4 className={`text-lg font-bold ${colors.text} mb-1`}>{vuln.title}</h4>
                              <span className={`${colors.bg} border ${colors.border} px-2 py-1 text-xs font-bold`}>
                                {(vuln.severity || 'HIGH').toUpperCase()} SEVERITY
                              </span>
                            </div>
                          </div>
                          <p className="text-sm opacity-70 mb-3">{vuln.description}</p>
                          {vuln.location && (
                            <div className="mb-2">
                              <div className="text-xs opacity-50 mb-1">LOCATION:</div>
                              <code className="text-xs bg-black p-2 block break-all">{vuln.location}</code>
                            </div>
                          )}
                          {vuln.evidence && (
                            <div className="mb-2">
                              <div className="text-xs opacity-50 mb-1">EVIDENCE:</div>
                              <code className="text-xs bg-black p-2 block break-all whitespace-pre-wrap">{vuln.evidence}</code>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* SQL Injection Vulnerabilities */}
          {vulnsByType['sqli'] && vulnsByType['sqli'].length > 0 && (
            <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
              <button
                onClick={() => toggleAccordion('sqli')}
                className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
              >
                <span className="text-xl font-bold glow-purple">[SQLI TESTING] ({vulnsByType['sqli'].length} found)</span>
                <span className="text-2xl">{openAccordions.includes('sqli') ? '▼' : '▶'}</span>
              </button>
              {openAccordions.includes('sqli') && (
                <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                  <div className="space-y-4">
                    {vulnsByType['sqli'].map((vuln: any, idx: number) => {
                      const sev = (vuln.severity || 'critical').toLowerCase();
                      const colors = severityColors[sev] || severityColors.critical;
                      return (
                        <div key={idx} className={`terminal-border ${colors.border} ${colors.bg} p-4`}>
                          <div className="flex items-start justify-between mb-3">
                            <div>
                              <h4 className={`text-lg font-bold ${colors.text} mb-1`}>{vuln.title}</h4>
                              <span className={`${colors.bg} border ${colors.border} px-2 py-1 text-xs font-bold`}>
                                {(vuln.severity || 'CRITICAL').toUpperCase()} SEVERITY
                              </span>
                            </div>
                          </div>
                          <p className="text-sm opacity-70 mb-3">{vuln.description}</p>
                          {vuln.location && (
                            <div className="mb-2">
                              <div className="text-xs opacity-50 mb-1">LOCATION:</div>
                              <code className="text-xs bg-black p-2 block break-all">{vuln.location}</code>
                            </div>
                          )}
                          {vuln.evidence && (
                            <div className="mb-2">
                              <div className="text-xs opacity-50 mb-1">EVIDENCE:</div>
                              <code className="text-xs bg-black p-2 block break-all whitespace-pre-wrap">{vuln.evidence}</code>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Auth & Access Control Vulnerabilities */}
          {((vulnsByType['auth'] && vulnsByType['auth'].length > 0) ||
            (vulnsByType['access-control'] && vulnsByType['access-control'].length > 0)) && (
            <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
              <button
                onClick={() => toggleAccordion('auth')}
                className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
              >
                <span className="text-xl font-bold glow-purple">
                  [AUTH & ACCESS CONTROL] ({(vulnsByType['auth']?.length || 0) + (vulnsByType['access-control']?.length || 0)} found)
                </span>
                <span className="text-2xl">{openAccordions.includes('auth') ? '▼' : '▶'}</span>
              </button>
              {openAccordions.includes('auth') && (
                <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                  <div className="space-y-4">
                    {[...(vulnsByType['auth'] || []), ...(vulnsByType['access-control'] || [])].map((vuln: any, idx: number) => {
                      const sev = (vuln.severity || 'high').toLowerCase();
                      const colors = severityColors[sev] || severityColors.high;
                      return (
                        <div key={idx} className={`terminal-border ${colors.border} ${colors.bg} p-4`}>
                          <div className="flex items-start justify-between mb-3">
                            <div>
                              <h4 className={`text-lg font-bold ${colors.text} mb-1`}>{vuln.title}</h4>
                              <span className={`${colors.bg} border ${colors.border} px-2 py-1 text-xs font-bold`}>
                                {(vuln.severity || 'HIGH').toUpperCase()} SEVERITY
                              </span>
                            </div>
                          </div>
                          <p className="text-sm opacity-70 mb-3">{vuln.description}</p>
                          {vuln.location && (
                            <div className="mb-2">
                              <div className="text-xs opacity-50 mb-1">LOCATION:</div>
                              <code className="text-xs bg-black p-2 block break-all">{vuln.location}</code>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Hidden/Sensitive Files */}
          {hiddenFiles.length > 0 && (
            <div className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
              <button
                onClick={() => toggleAccordion('files')}
                className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
              >
                <span className="text-xl font-bold glow-purple">[SENSITIVE FILES] ({hiddenFiles.length} found)</span>
                <span className="text-2xl">{openAccordions.includes('files') ? '▼' : '▶'}</span>
              </button>
              {openAccordions.includes('files') && (
                <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                  <div className="space-y-4">
                    {hiddenFiles.map((file: any, idx: number) => {
                      const sev = (file.severity || 'medium').toLowerCase();
                      const colors = severityColors[sev] || severityColors.medium;
                      return (
                        <div key={idx} className={`terminal-border ${colors.border} ${colors.bg} p-4`}>
                          <div className="flex items-start justify-between mb-3">
                            <div>
                              <h4 className={`text-lg font-bold ${colors.text} mb-1`}>{file.title || file.path}</h4>
                              <span className={`${colors.bg} border ${colors.border} px-2 py-1 text-xs font-bold`}>
                                {(file.severity || 'MEDIUM').toUpperCase()} SEVERITY
                              </span>
                            </div>
                          </div>
                          <p className="text-sm opacity-70 mb-3">{file.description}</p>
                          <div className="mb-2">
                            <div className="text-xs opacity-50 mb-1">PATH:</div>
                            <code className="text-xs bg-black p-2 block break-all">{file.path}</code>
                          </div>
                          {file.recommendation && (
                            <div>
                              <div className="text-xs opacity-50 mb-1">RECOMMENDATION:</div>
                              <p className="text-xs opacity-70">{file.recommendation}</p>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Other Vulnerabilities */}
          {Object.entries(vulnsByType)
            .filter(([type]) => !['security-header', 'xss', 'sqli', 'auth', 'access-control'].includes(type))
            .map(([type, vulns]) => (
              vulns.length > 0 && (
                <div key={type} className="terminal-border bg-black/80 backdrop-blur overflow-hidden">
                  <button
                    onClick={() => toggleAccordion(type)}
                    className="w-full p-4 flex items-center justify-between hover:bg-purple-900/20 transition-all"
                  >
                    <span className="text-xl font-bold glow-purple">[{type.toUpperCase()}] ({vulns.length} found)</span>
                    <span className="text-2xl">{openAccordions.includes(type) ? '▼' : '▶'}</span>
                  </button>
                  {openAccordions.includes(type) && (
                    <div className="p-6 border-t-2 border-purple-600 bg-black/50">
                      <div className="space-y-4">
                        {vulns.map((vuln: any, idx: number) => {
                          const sev = (vuln.severity || 'medium').toLowerCase();
                          const colors = severityColors[sev] || severityColors.medium;
                          return (
                            <div key={idx} className={`terminal-border ${colors.border} ${colors.bg} p-4`}>
                              <div className="flex items-start justify-between mb-3">
                                <div>
                                  <h4 className={`text-lg font-bold ${colors.text} mb-1`}>{vuln.title}</h4>
                                  <span className={`${colors.bg} border ${colors.border} px-2 py-1 text-xs font-bold`}>
                                    {(vuln.severity || 'MEDIUM').toUpperCase()} SEVERITY
                                  </span>
                                </div>
                              </div>
                              <p className="text-sm opacity-70 mb-3">{vuln.description}</p>
                              {vuln.location && (
                                <div className="mb-2">
                                  <div className="text-xs opacity-50 mb-1">LOCATION:</div>
                                  <code className="text-xs bg-black p-2 block break-all">{vuln.location}</code>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              )
            ))}

          {/* No vulnerabilities message */}
          {vulnerabilities.length === 0 && hiddenFiles.length === 0 && (
            <div className="terminal-border bg-green-900/20 border-green-600 p-6 text-center">
              <div className="text-4xl mb-4">✓</div>
              <div className="text-xl font-bold text-green-400 mb-2">No Vulnerabilities Found</div>
              <p className="text-sm opacity-70">
                The scan completed without finding any security issues. However, this doesn't guarantee complete security.
                Consider running additional manual tests.
              </p>
            </div>
          )}
        </div>

        {/* Recommendations based on actual findings */}
        {vulnerabilities.length > 0 && (
          <div className="terminal-border bg-purple-900/20 backdrop-blur p-6 mb-8">
            <h2 className="text-2xl font-bold mb-4 glow-purple">[RECOMMENDATIONS]</h2>
            <div className="space-y-4">
              {vulnCounts.critical > 0 && (
                <div className="flex gap-4 p-4 bg-red-900/20 border border-red-600">
                  <span className="text-2xl font-bold text-red-400">!</span>
                  <div>
                    <div className="font-bold mb-1 text-red-400">Critical vulnerabilities require immediate attention</div>
                    <p className="text-sm opacity-70">
                      You have {vulnCounts.critical} critical issue(s). These should be fixed before deploying to production.
                    </p>
                  </div>
                </div>
              )}
              {vulnsByType['security-header'] && (
                <div className="flex gap-4">
                  <span className="text-2xl font-bold text-yellow-400">1.</span>
                  <div>
                    <div className="font-bold mb-1">Add missing security headers</div>
                    <p className="text-sm opacity-70 mb-2">
                      Configure your web server or application to include security headers like CSP, HSTS, X-Frame-Options.
                    </p>
                    <a
                      href="https://owasp.org/www-project-secure-headers/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-purple-400 text-xs hover:underline"
                    >
                      OWASP Secure Headers Guide
                    </a>
                  </div>
                </div>
              )}
              {vulnsByType['xss'] && (
                <div className="flex gap-4">
                  <span className="text-2xl font-bold text-orange-400">2.</span>
                  <div>
                    <div className="font-bold mb-1">Fix XSS vulnerabilities</div>
                    <p className="text-sm opacity-70 mb-2">
                      Sanitize all user inputs and use proper output encoding. Consider implementing a Content Security Policy.
                    </p>
                    <a
                      href="https://owasp.org/www-community/attacks/xss/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-purple-400 text-xs hover:underline"
                    >
                      OWASP XSS Prevention Guide
                    </a>
                  </div>
                </div>
              )}
              {vulnsByType['sqli'] && (
                <div className="flex gap-4">
                  <span className="text-2xl font-bold text-red-400">3.</span>
                  <div>
                    <div className="font-bold mb-1">Fix SQL Injection vulnerabilities</div>
                    <p className="text-sm opacity-70 mb-2">
                      Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.
                    </p>
                    <a
                      href="https://owasp.org/www-community/attacks/SQL_Injection"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-purple-400 text-xs hover:underline"
                    >
                      OWASP SQL Injection Guide
                    </a>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex flex-wrap justify-center gap-4">
          <Link
            href={`/scan?url=${encodeURIComponent(scan.target)}`}
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
