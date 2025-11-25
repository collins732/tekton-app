'use client';

import { useState } from 'react';

interface TokenPurchaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (paymentMethod: string) => void;
  tokenPack: {
    tokens: number;
    price: string;
  } | null;
}

export default function TokenPurchaseModal({ isOpen, onClose, onConfirm, tokenPack }: TokenPurchaseModalProps) {
  const [selectedPayment, setSelectedPayment] = useState<string>('stripe');
  const [isProcessing, setIsProcessing] = useState(false);

  if (!isOpen || !tokenPack) return null;

  const handleConfirm = async () => {
    setIsProcessing(true);
    await onConfirm(selectedPayment);
    setIsProcessing(false);
  };

  const paymentMethods = [
    { id: 'stripe', name: 'CREDIT CARD', icon: '[CC]', description: 'Visa, Mastercard, Amex' },
    { id: 'paypal', name: 'PAYPAL', icon: '[PP]', description: 'Pay with PayPal balance' },
    { id: 'crypto', name: 'CRYPTO', icon: '[฿]', description: 'BTC, ETH, USDT' }
  ];

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/90 backdrop-blur-sm animate-fade-in">
      <div className="terminal-border bg-black/95 backdrop-blur p-8 max-w-2xl mx-4 animate-scale-in">
        {/* Header */}
        <div className="mb-6 text-center">
          <div className="text-purple-400 text-4xl mb-2 font-mono">[+]</div>
          <h2 className="text-2xl font-bold glow-purple">PURCHASE CONFIRMATION</h2>
        </div>

        {/* Purchase Details */}
        <div className="terminal-border border-purple-600 bg-purple-900/10 p-6 mb-6">
          <div className="grid grid-cols-2 gap-4 text-center mb-4">
            <div>
              <div className="text-sm opacity-50 mb-1">TOKENS</div>
              <div className="text-3xl font-bold text-purple-400">{tokenPack.tokens}</div>
            </div>
            <div>
              <div className="text-sm opacity-50 mb-1">TOTAL</div>
              <div className="text-3xl font-bold text-green-400">{tokenPack.price}€</div>
            </div>
          </div>
          <div className="text-center text-xs opacity-50">
            {(parseFloat(tokenPack.price) / tokenPack.tokens).toFixed(3)}€ per token
          </div>
        </div>

        {/* Payment Method Selection */}
        <div className="mb-6">
          <h3 className="text-lg font-bold mb-4 text-purple-400">SELECT PAYMENT METHOD</h3>
          <div className="space-y-3">
            {paymentMethods.map((method) => (
              <label
                key={method.id}
                className={`flex items-center gap-4 p-4 cursor-pointer transition-all border-2 ${
                  selectedPayment === method.id
                    ? 'border-purple-400 bg-purple-900/20'
                    : 'border-gray-700 bg-black/50 hover:border-gray-600'
                }`}
              >
                <input
                  type="radio"
                  name="payment"
                  value={method.id}
                  checked={selectedPayment === method.id}
                  onChange={(e) => setSelectedPayment(e.target.value)}
                  className="w-5 h-5 accent-purple-600"
                />
                <div className="text-2xl">{method.icon}</div>
                <div className="flex-1">
                  <div className="font-bold">{method.name}</div>
                  <div className="text-xs opacity-50">{method.description}</div>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Info Notice */}
        <div className="terminal-border border-yellow-600 bg-yellow-900/10 p-4 mb-6">
          <div className="flex items-start gap-3 text-sm">
            <span className="text-yellow-400 font-bold">[!]</span>
            <div className="text-yellow-200">
              <p className="font-bold mb-1">DEMO MODE</p>
              <p className="opacity-70">This is a demonstration. No real payment will be processed. Tokens will be added to your account for testing purposes.</p>
            </div>
          </div>
        </div>

        {/* Buttons */}
        <div className="flex gap-4">
          <button
            onClick={onClose}
            disabled={isProcessing}
            className="flex-1 py-3 font-bold font-mono transition-all border-2 border-gray-600 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            [CANCEL]
          </button>
          <button
            onClick={handleConfirm}
            disabled={isProcessing}
            className={`flex-1 py-3 font-bold font-mono transition-all border-2 ${
              isProcessing
                ? 'bg-gray-700 border-gray-600 text-gray-400 cursor-not-allowed'
                : 'bg-purple-600 hover:bg-purple-500 border-purple-400 glow-purple'
            }`}
          >
            {isProcessing ? '[PROCESSING...]' : '[CONFIRM PURCHASE]'}
          </button>
        </div>
      </div>
    </div>
  );
}
