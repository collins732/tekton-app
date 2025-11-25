'use client';

import { useState } from 'react';

interface LegalWarningModalProps {
  isOpen: boolean;
  onAccept: () => void;
  onClose: () => void;
}

export default function LegalWarningModal({ isOpen, onAccept, onClose }: LegalWarningModalProps) {
  const [termsAccepted, setTermsAccepted] = useState(false);

  if (!isOpen) return null;

  const handleAccept = () => {
    if (termsAccepted) {
      onAccept();
    }
  };

  // Prevent closing by clicking outside
  const handleBackdropClick = (e: React.MouseEvent) => {
    e.stopPropagation();
  };

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/90 backdrop-blur-sm animate-fade-in"
      onClick={handleBackdropClick}
    >
      <div className="terminal-border bg-black/95 backdrop-blur p-8 max-w-xl mx-4 animate-scale-in">
        {/* Header */}
        <div className="mb-6 text-center">
          <div className="text-red-400 text-4xl mb-2 font-mono">[!]</div>
          <h2 className="text-2xl font-bold glow-purple">{'>_'} AUTHORIZATION REQUIRED</h2>
        </div>

        {/* Content */}
        <div className="terminal-border border-red-600 bg-red-900/10 p-4 mb-6">
          <div className="space-y-3 text-sm font-mono">
            <p className="text-yellow-400">
              {'>'} You must have <span className="text-purple-400 font-bold">EXPLICIT PERMISSION</span> to scan:
            </p>

            <div className="pl-4 space-y-1 text-gray-300">
              <p>{'[+]'} Your own websites/apps</p>
              <p>{'[+]'} Sites with written authorization</p>
              <p>{'[+]'} Authorized test environments</p>
            </div>

            <div className="border-t border-red-600 my-3 pt-3">
              <p className="text-red-400 font-bold">
                {'[!]'} Unauthorized scanning is <span className="underline">ILLEGAL</span>
              </p>
            </div>
          </div>
        </div>

        {/* Terms Checkbox */}
        <div className="mb-6">
          <label className="flex items-start gap-3 cursor-pointer hover:bg-purple-900/10 p-3 rounded transition-all">
            <input
              type="checkbox"
              checked={termsAccepted}
              onChange={(e) => setTermsAccepted(e.target.checked)}
              className="mt-1 w-5 h-5 bg-black border-2 border-purple-600 rounded
                       checked:bg-purple-600 checked:border-purple-400
                       focus:outline-none focus:ring-2 focus:ring-purple-400
                       cursor-pointer accent-purple-600"
            />
            <span className="text-sm leading-relaxed font-mono">
              I confirm that I have <span className="text-purple-400 font-bold">explicit authorization</span> to scan
              the target website/application, and I understand that <span className="text-red-400 font-bold">unauthorized
              scanning is illegal</span> and may result in criminal prosecution.
            </span>
          </label>
        </div>

        {/* Buttons */}
        <div className="flex gap-4">
          <button
            onClick={handleAccept}
            disabled={!termsAccepted}
            className={`flex-1 py-3 font-bold font-mono transition-all border-2 ${
              termsAccepted
                ? 'bg-purple-600 hover:bg-purple-500 border-purple-400 cursor-pointer glow-purple'
                : 'bg-gray-700 border-gray-600 text-gray-400 cursor-not-allowed opacity-50'
            }`}
          >
            {termsAccepted ? '[ACCEPT & CONTINUE]' : '[CHECK BOX TO CONTINUE]'}
          </button>
        </div>
      </div>
    </div>
  );
}
