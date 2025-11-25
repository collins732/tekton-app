'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import TokenPurchaseModal from '@/components/TokenPurchaseModal';
import TokenPurchaseSuccessModal from '@/components/TokenPurchaseSuccessModal';

export default function BuyTokensPage() {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [showPurchaseModal, setShowPurchaseModal] = useState(false);
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [selectedPack, setSelectedPack] = useState<{tokens: number; price: string} | null>(null);
  const [purchaseResult, setPurchaseResult] = useState<{tokens: number; newBalance: number} | null>(null);

  // Check authentication and load user data
  useEffect(() => {
    const loadUserData = async () => {
      try {
        const response = await fetch('/api/auth/session');
        const sessionData = await response.json();

        if (!sessionData.authenticated || !sessionData.user) {
          router.push('/login');
          return;
        }

        const userResponse = await fetch('/api/user');
        if (userResponse.ok) {
          const data = await userResponse.json();
          setUser(data);
        }
      } catch (error) {
        console.error('Failed to load user data:', error);
        router.push('/login');
      } finally {
        setLoading(false);
      }
    };

    loadUserData();
  }, [router]);

  const handleBuyClick = (pack: {tokens: number; price: string}) => {
    setSelectedPack(pack);
    setShowPurchaseModal(true);
  };

  const handlePurchaseConfirm = async (paymentMethod: string) => {
    if (!selectedPack) return;

    try {
      const response = await fetch('/api/tokens/purchase', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tokens: selectedPack.tokens,
          price: selectedPack.price,
          paymentMethod
        }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // Update local user data
        setUser((prev: any) => ({
          ...prev,
          tokens: data.new_balance
        }));

        // Store purchase result for success modal
        setPurchaseResult({
          tokens: data.tokens_added,
          newBalance: data.new_balance
        });

        // Close purchase modal and show success modal
        setShowPurchaseModal(false);
        setShowSuccessModal(true);
      } else {
        alert(`Error: ${data.error || 'Failed to purchase tokens'}`);
      }
    } catch (error) {
      console.error('Purchase error:', error);
      alert('An error occurred while processing your purchase');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="terminal-border bg-black/90 backdrop-blur p-8 text-center">
          <div className="text-purple-400 text-4xl mb-4 animate-pulse">[*]</div>
          <div className="text-lg glow-purple">LOADING...</div>
        </div>
      </div>
    );
  }
  const tokenPacks = [
    {
      tokens: 100,
      price: '9.99',
      badge: null,
      popular: false
    },
    {
      tokens: 250,
      price: '19.99',
      badge: 'SAVE 20%',
      popular: false
    },
    {
      tokens: 500,
      price: '34.99',
      badge: 'POPULAR - SAVE 30%',
      popular: true
    },
    {
      tokens: 1000,
      price: '59.99',
      badge: 'BEST VALUE - SAVE 40%',
      popular: false
    }
  ];

  const paymentMethods = [
    { name: 'STRIPE', icon: '' },
    { name: 'PAYPAL', icon: '' },
    { name: 'CRYPTO', icon: '฿' }
  ];

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-4xl md:text-5xl font-bold mb-4 glow-purple">
            [BUY TOKENS]
          </h1>
          <p className="text-xl opacity-70 mb-2">
            Purchase additional tokens to power your security scans
          </p>
          <p className="text-sm opacity-50">
            Tokens never expire and can be used anytime
          </p>
        </div>

        {/* Current Balance */}
        <div className="terminal-border bg-purple-900/20 backdrop-blur p-6 mb-12 text-center">
          <div className="text-sm opacity-50 mb-2">YOUR CURRENT BALANCE</div>
          <div className="flex items-center justify-center gap-3">
            <span className="text-6xl font-bold glow-green">{user?.tokens || 0}</span>
            <span className="text-4xl text-purple-400">[⚡]</span>
            <span className="text-xl opacity-50">tokens</span>
          </div>
        </div>

        {/* Token Packs */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          {tokenPacks.map((pack, index) => (
            <div
              key={index}
              className={`terminal-border bg-black/80 backdrop-blur p-6 relative transition-all hover:scale-105 ${
                pack.popular ? 'border-4 border-purple-400' : ''
              }`}
            >
              {/* Badge */}
              {pack.badge && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-purple-600 px-3 py-1 text-xs font-bold animate-pulse whitespace-nowrap">
                  {pack.badge}
                </div>
              )}

              {/* 3D Icon Placeholder */}
              <div className="placeholder-3d-icon bg-purple-900/20 h-32 w-32 mx-auto mb-4 flex items-center justify-center border border-purple-600">
                <span className="text-4xl">[T]</span>
              </div>

              {/* Tokens */}
              <div className="text-center mb-4">
                <div className="text-4xl font-bold glow-purple mb-1">{pack.tokens}</div>
                <div className="text-sm opacity-50">TOKENS</div>
              </div>

              {/* Price */}
              <div className="text-center mb-6 pb-6 border-b border-purple-600">
                <span className="text-3xl font-bold glow-green">{pack.price}€</span>
              </div>

              {/* Value per token */}
              <div className="text-center text-xs opacity-50 mb-4">
                {(parseFloat(pack.price) / pack.tokens).toFixed(3)}€ per token
              </div>

              {/* Buy Button */}
              <button
                onClick={() => handleBuyClick(pack)}
                className="w-full py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
              >
                [BUY NOW]
              </button>
            </div>
          ))}
        </div>

        {/* Payment Methods */}
        <div className="terminal-border bg-black/80 backdrop-blur p-8 mb-12">
          <h2 className="text-2xl font-bold text-center mb-6 glow-purple">
            ACCEPTED PAYMENT METHODS
          </h2>
          <div className="flex flex-wrap justify-center gap-8">
            {paymentMethods.map((method, index) => (
              <div key={index} className="text-center">
                {method.icon && <div className="text-5xl mb-2">{method.icon}</div>}
                <div className="text-lg font-bold text-purple-400">{method.name}</div>
              </div>
            ))}
          </div>
        </div>

        {/* FAQ */}
        <div className="terminal-border bg-black/80 backdrop-blur p-8 mb-12">
          <h2 className="text-2xl font-bold mb-6 glow-purple text-center">
            [TOKEN FAQ]
          </h2>

          <div className="space-y-6 max-w-3xl mx-auto">
            <div>
              <h3 className="text-lg font-bold text-purple-400 mb-2">
                Do purchased tokens expire?
              </h3>
              <p className="text-sm opacity-70">
                No! Tokens you purchase separately never expire. Only monthly plan tokens reset each billing cycle.
                Your purchased tokens will remain in your account indefinitely.
              </p>
            </div>

            <div>
              <h3 className="text-lg font-bold text-purple-400 mb-2">
                Can I get a refund?
              </h3>
              <p className="text-sm opacity-70">
                Unused tokens can be refunded within 30 days of purchase. Once tokens are used for scans,
                they cannot be refunded.
              </p>
            </div>

            <div>
              <h3 className="text-lg font-bold text-purple-400 mb-2">
                How do tokens work with my plan?
              </h3>
              <p className="text-sm opacity-70">
                Purchased tokens are used after your monthly plan tokens. Your plan tokens reset monthly,
                while purchased tokens persist. This ensures you always use expiring tokens first.
              </p>
            </div>

            <div>
              <h3 className="text-lg font-bold text-purple-400 mb-2">
                Is payment secure?
              </h3>
              <p className="text-sm opacity-70">
                Yes! All payments are processed through industry-standard encrypted payment gateways.
                We never store your payment information on our servers.
              </p>
            </div>
          </div>
        </div>

        {/* Need More? */}
        <div className="terminal-border bg-purple-900/20 backdrop-blur p-8 text-center">
          <h2 className="text-3xl font-bold mb-4 glow-purple">
            NEED MORE TOKENS?
          </h2>
          <p className="text-lg opacity-70 mb-6">
            Consider upgrading to a higher plan for better value
          </p>
          <Link
            href="/pricing"
            className="inline-block px-8 py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all"
          >
            [VIEW PLANS]
          </Link>
        </div>
      </div>

      {/* Purchase Modal */}
      <TokenPurchaseModal
        isOpen={showPurchaseModal}
        onClose={() => setShowPurchaseModal(false)}
        onConfirm={handlePurchaseConfirm}
        tokenPack={selectedPack}
      />

      {/* Success Modal */}
      <TokenPurchaseSuccessModal
        isOpen={showSuccessModal}
        onClose={() => setShowSuccessModal(false)}
        tokensPurchased={purchaseResult?.tokens || 0}
        newBalance={purchaseResult?.newBalance || 0}
      />
    </div>
  );
}
