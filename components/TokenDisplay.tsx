'use client';

interface TokenDisplayProps {
  current: number;
  limit?: number;
  showProgress?: boolean;
}

export default function TokenDisplay({ current, limit, showProgress = false }: TokenDisplayProps) {
  const percentage = limit ? (current / limit) * 100 : 0;

  return (
    <div className="terminal-border bg-black/80 backdrop-blur p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm opacity-50 mb-1">AVAILABLE TOKENS</h3>
          <div className="flex items-center gap-2">
            <span className="text-4xl font-bold glow-green">{current}</span>
            {limit && (
              <>
                <span className="text-2xl opacity-50">/</span>
                <span className="text-2xl opacity-50">{limit}</span>
              </>
            )}
            <span className="text-2xl text-purple-400">⚡</span>
          </div>
        </div>
      </div>

      {showProgress && limit && (
        <div className="w-full">
          <div className="h-2 bg-gray-800 terminal-border overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-purple-600 to-green-500 transition-all duration-300"
              style={{ width: `${percentage}%` }}
            />
          </div>
          <p className="text-xs opacity-50 mt-2 text-right">{percentage.toFixed(0)}% remaining</p>
        </div>
      )}
    </div>
  );
}
