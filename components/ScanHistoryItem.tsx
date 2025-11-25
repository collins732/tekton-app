'use client';

import { useRouter } from 'next/navigation';

interface ScanHistoryItemProps {
  scan_id: string;
  target: string;
  started_at: number;
  status: 'completed' | 'failed' | 'running' | 'pending';
  error?: string;
  results?: any;
  cost: number;
}

export default function ScanHistoryItem({
  scan_id,
  target,
  started_at,
  status,
  error,
  results,
  cost
}: ScanHistoryItemProps) {
  const router = useRouter();

  // Format date
  const date = new Date(started_at).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });

  // Count vulnerabilities from results
  let vulnerabilities = { high: 0, medium: 0, low: 0 };
  if (results) {
    const parsedResults = typeof results === 'string' ? JSON.parse(results) : results;

    // Count from XSS results
    if (parsedResults.xss_results?.vulnerabilities) {
      parsedResults.xss_results.vulnerabilities.forEach((v: any) => {
        if (v.severity === 'high' || v.severity === 'HIGH') vulnerabilities.high++;
        else if (v.severity === 'medium' || v.severity === 'MEDIUM') vulnerabilities.medium++;
        else vulnerabilities.low++;
      });
    }

    // Count from SQL injection results
    if (parsedResults.sqli_results?.vulnerabilities) {
      parsedResults.sqli_results.vulnerabilities.forEach((v: any) => {
        if (v.severity === 'high' || v.severity === 'HIGH') vulnerabilities.high++;
        else if (v.severity === 'medium' || v.severity === 'MEDIUM') vulnerabilities.medium++;
        else vulnerabilities.low++;
      });
    }
  }

  const handleView = () => {
    router.push(`/scan/${scan_id}`);
  };

  const handleRescan = () => {
    router.push(`/scan?url=${encodeURIComponent(target)}`);
  };

  const handleRetry = () => {
    router.push(`/scan?url=${encodeURIComponent(target)}`);
  };

  const handleViewError = () => {
    alert(`Scan Error:\n\n${error || 'Unknown error'}`);
  };
  const statusConfig = {
    completed: { color: 'text-green-400', icon: '[✓]', label: 'COMPLETED' },
    failed: { color: 'text-red-400', icon: '[✗]', label: 'FAILED' },
    running: { color: 'text-purple-400', icon: '[⟳]', label: 'RUNNING' },
    pending: { color: 'text-yellow-400', icon: '[...]', label: 'PENDING' }
  };

  const config = statusConfig[status];

  return (
    <div className="terminal-border bg-black/80 backdrop-blur p-4 hover:border-purple-300 transition-all">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        {/* Left: URL & Date */}
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className={`font-bold ${config.color}`}>{config.icon}</span>
            <h4 className="font-bold glow-purple truncate">{target}</h4>
          </div>
          <p className="text-xs opacity-50">{date}</p>
          {status === 'failed' && error && (
            <p className="text-xs text-red-400 mt-1">Error: {error}</p>
          )}
        </div>

        {/* Middle: Vulnerabilities */}
        {vulnerabilities && status === 'completed' && (
          <div className="flex gap-4">
            <div className="text-center">
              <div className="text-xl font-bold text-red-400">{vulnerabilities.high}</div>
              <div className="text-xs opacity-50">HIGH</div>
            </div>
            <div className="text-center">
              <div className="text-xl font-bold text-yellow-400">{vulnerabilities.medium}</div>
              <div className="text-xs opacity-50">MEDIUM</div>
            </div>
            {vulnerabilities.low !== undefined && (
              <div className="text-center">
                <div className="text-xl font-bold text-blue-400">{vulnerabilities.low}</div>
                <div className="text-xs opacity-50">LOW</div>
              </div>
            )}
          </div>
        )}

        {/* Right: Cost & Actions */}
        <div className="flex items-center gap-4">
          <div className="text-center">
            <div className="text-sm text-purple-400 font-bold">{cost} [⚡]</div>
            <div className="text-xs opacity-50">tokens</div>
          </div>

          {/* Actions selon status */}
          <div className="flex gap-2">
            {status === 'completed' && (
              <>
                <button
                  onClick={handleView}
                  className="px-3 py-1 bg-purple-600 hover:bg-purple-500 border border-purple-400 text-xs font-bold transition-all"
                >
                  [VIEW]
                </button>
                <button
                  onClick={handleRescan}
                  className="px-3 py-1 bg-black hover:bg-gray-900 border border-purple-400 text-xs font-bold transition-all"
                >
                  [RE-SCAN]
                </button>
              </>
            )}

            {(status === 'running' || status === 'pending') && (
              <>
                <button
                  onClick={handleView}
                  className="px-3 py-1 bg-purple-600 hover:bg-purple-500 border border-purple-400 text-xs font-bold transition-all"
                >
                  [VIEW PROGRESS]
                </button>
              </>
            )}

            {status === 'failed' && (
              <>
                <button
                  onClick={handleViewError}
                  className="px-3 py-1 bg-orange-600 hover:bg-orange-500 border border-orange-400 text-xs font-bold transition-all"
                >
                  [VIEW ERROR]
                </button>
                <button
                  onClick={handleRetry}
                  className="px-3 py-1 bg-red-600 hover:bg-red-500 border border-red-400 text-xs font-bold transition-all"
                >
                  [RETRY]
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
