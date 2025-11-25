'use client';

interface PricingCardProps {
  name: string;
  price: string;
  tokens: number;
  features: string[];
  badge?: string;
  badgeColor?: string;
  popular?: boolean;
  accentColor?: string;
}

export default function PricingCard({
  name,
  price,
  tokens,
  features,
  badge,
  badgeColor = 'bg-purple-600',
  popular = false,
  accentColor = 'border-purple-400'
}: PricingCardProps) {
  return (
    <div className={`${popular ? 'terminal-border-strong' : 'terminal-border'} bg-black/80 backdrop-blur p-6 relative transition-all hover:scale-105`}>
      {/* Badge */}
      {badge && (
        <div className={`absolute -top-3 left-1/2 -translate-x-1/2 ${badgeColor} px-4 py-1 text-xs font-bold animate-pulse`}>
          {badge}
        </div>
      )}

      {/* 3D Icon Placeholder */}
      <div className="placeholder-3d-icon bg-purple-900/20 h-32 w-32 mx-auto mb-4 flex items-center justify-center terminal-border">
        <span className="text-sm opacity-50">[3D ICON]</span>
      </div>

      {/* Plan Name */}
      <h3 className="text-3xl font-bold text-center mb-2 glow-purple">{name}</h3>

      {/* Price */}
      <div className="text-center mb-4">
        <span className="text-5xl font-bold glow-green">{price}</span>
        {price !== 'FREE' && <span className="text-sm opacity-50">/month</span>}
      </div>

      {/* Tokens */}
      <div className="text-center mb-6 pb-6 border-b border-purple-600">
        <span className="text-2xl font-bold text-purple-400">{tokens}</span>
        <span className="text-sm opacity-50"> tokens/month</span>
      </div>

      {/* Practical Value */}
      <div className="text-center mb-6 text-xs opacity-70">
        <div className="text-purple-400 font-bold mb-1">What you can do:</div>
        <div>~{Math.floor(tokens / 40)} basic scans</div>
        <div>~{Math.floor(tokens / 100)} full scans</div>
      </div>

      {/* Features */}
      <ul className="space-y-3 mb-6">
        {features.map((feature, index) => (
          <li key={index} className="flex items-start gap-2">
            <span className="text-green-400 mt-1">✓</span>
            <span className="text-sm">{feature}</span>
          </li>
        ))}
      </ul>

      {/* CTA Button */}
      <button
        onClick={() => console.log(`TODO: Select ${name} plan`)}
        className="w-full py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all glow-purple"
      >
        [SELECT PLAN]
      </button>
    </div>
  );
}
