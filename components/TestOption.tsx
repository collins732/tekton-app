'use client';

interface TestOptionProps {
  name: string;
  description: string;
  cost: number;
  selected: boolean;
  locked?: boolean;
  lockReason?: string;
  onToggle: () => void;
}

export default function TestOption({
  name,
  description,
  cost,
  selected,
  locked = false,
  lockReason,
  onToggle
}: TestOptionProps) {
  return (
    <div
      onClick={locked ? undefined : onToggle}
      className={`
        ${selected ? 'terminal-border-strong border-green-400 bg-green-900/20' : 'terminal-border hover:border-purple-300'} bg-black/80 backdrop-blur p-4 relative transition-all cursor-pointer
        ${locked ? 'opacity-50 cursor-not-allowed' : ''}
      `}
    >
      {/* Lock Overlay */}
      {locked && (
        <div className="absolute inset-0 bg-black/40 backdrop-blur-sm flex items-start justify-end p-2 z-10 transition-all hover:bg-black/30">
          {/* Lock Badge - Top Right */}
          <div className="bg-red-600 px-2 py-1 flex items-center gap-1">
            <span className="text-sm">[LOCKED]</span>
            <span className="text-xs font-bold">{lockReason}</span>
          </div>
        </div>
      )}

      {/* Checkbox */}
      <div className="absolute top-4 right-4">
        <div className={`w-6 h-6 border-2 ${selected ? 'bg-green-400 border-green-400' : 'border-purple-400'} flex items-center justify-center`}>
          {selected && <span className="text-black font-bold">✓</span>}
        </div>
      </div>

      {/* 3D Icon Placeholder */}
      <div className="placeholder-3d-icon bg-purple-900/20 h-20 w-20 mx-auto mb-3 flex items-center justify-center border border-purple-600">
        <span className="text-xs opacity-50">[3D]</span>
      </div>

      {/* Name */}
      <h4 className="text-lg font-bold text-center mb-1 glow-purple">{name}</h4>

      {/* Description */}
      <p className="text-xs opacity-70 text-center mb-3">{description}</p>

      {/* Cost */}
      <div className="text-center">
        <span className="text-purple-400 font-bold">{cost}</span>
        <span className="text-xs opacity-50"> tokens</span>
      </div>
    </div>
  );
}
