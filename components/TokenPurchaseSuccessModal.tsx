'use client';

interface TokenPurchaseSuccessModalProps {
  isOpen: boolean;
  onClose: () => void;
  tokensPurchased: number;
  newBalance: number;
}

export default function TokenPurchaseSuccessModal({
  isOpen,
  onClose,
  tokensPurchased,
  newBalance
}: TokenPurchaseSuccessModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/90 backdrop-blur-sm animate-fade-in">
      <div className="terminal-border bg-black/95 backdrop-blur p-8 max-w-xl mx-4 animate-scale-in">
        {/* Header */}
        <div className="mb-6 text-center">
          <div className="text-green-400 text-6xl mb-4 animate-pulse">[✓]</div>
          <h2 className="text-3xl font-bold glow-green mb-2">PURCHASE SUCCESSFUL!</h2>
          <p className="text-sm opacity-70">Your tokens have been added to your account</p>
        </div>

        {/* Success Details */}
        <div className="terminal-border border-green-600 bg-green-900/10 p-6 mb-6">
          <div className="text-center mb-4">
            <div className="text-sm opacity-50 mb-2">TOKENS ADDED</div>
            <div className="text-5xl font-bold text-green-400 mb-4">+{tokensPurchased}</div>
          </div>

          <div className="border-t border-green-600 pt-4 text-center">
            <div className="text-sm opacity-50 mb-2">NEW BALANCE</div>
            <div className="flex items-center justify-center gap-3">
              <span className="text-4xl font-bold glow-purple">{newBalance}</span>
              <span className="text-2xl text-purple-400">[⚡]</span>
            </div>
          </div>
        </div>

        {/* Info */}
        <div className="terminal-border border-purple-600 bg-purple-900/10 p-4 mb-6">
          <div className="text-sm text-center space-y-2">
            <p>{'[+]'} Tokens never expire</p>
            <p>{'[+]'} Ready to use immediately</p>
            <p>{'[+]'} Receipt sent to your email</p>
          </div>
        </div>

        {/* Button */}
        <button
          onClick={onClose}
          className="w-full py-3 font-bold font-mono transition-all border-2 bg-purple-600 hover:bg-purple-500 border-purple-400 glow-purple"
        >
          [CONTINUE]
        </button>
      </div>
    </div>
  );
}
