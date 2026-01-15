'use client';

import { useSearchParams, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';

interface PlanDetails {
  name: string;
  price: string;
  tokens: number;
}

export default function PaymentPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [planDetails, setPlanDetails] = useState<PlanDetails | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const plan = searchParams.get('plan');
    const price = searchParams.get('price');
    const tokens = searchParams.get('tokens');

    if (!plan || !price || !tokens) {
      router.push('/pricing');
      return;
    }

    setPlanDetails({
      name: plan,
      price: price,
      tokens: parseInt(tokens, 10)
    });
  }, [searchParams, router]);

  const handlePayment = async () => {
    setLoading(true);

    // Simulate payment processing
    await new Promise(resolve => setTimeout(resolve, 2000));

    // TODO: Implement actual payment processing
    console.log('Processing payment for plan:', planDetails);

    setLoading(false);
    alert(`Payment simulation complete for ${planDetails?.name} plan!`);
  };

  if (!planDetails) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-2xl animate-pulse">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen py-20 px-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <h1 className="text-5xl font-bold mb-8 text-center glow-purple">
          [COMPLETE YOUR PURCHASE]
        </h1>

        {/* Plan Summary */}
        <div className="terminal-border bg-black/80 backdrop-blur p-8 mb-8">
          <h2 className="text-2xl font-bold mb-4 text-purple-400">
            ORDER SUMMARY
          </h2>

          <div className="space-y-4">
            <div className="flex justify-between py-2 border-b border-purple-600">
              <span className="opacity-70">Plan</span>
              <span className="font-bold">{planDetails.name}</span>
            </div>

            <div className="flex justify-between py-2 border-b border-purple-600">
              <span className="opacity-70">Monthly Tokens</span>
              <span className="font-bold">{planDetails.tokens}</span>
            </div>

            <div className="flex justify-between py-2 text-2xl">
              <span className="opacity-70">Total</span>
              <span className="font-bold glow-green">
                {planDetails.price}
                {planDetails.price !== 'FREE' && '/month'}
              </span>
            </div>
          </div>
        </div>

        {/* Payment Form */}
        {planDetails.price !== 'FREE' && (
          <div className="terminal-border bg-black/80 backdrop-blur p-8 mb-8">
            <h2 className="text-2xl font-bold mb-6 text-purple-400">
              PAYMENT INFORMATION
            </h2>

            <form className="space-y-6" onSubmit={(e) => { e.preventDefault(); handlePayment(); }}>
              {/* Email */}
              <div>
                <label className="block text-sm font-bold mb-2 opacity-70">
                  EMAIL ADDRESS
                </label>
                <input
                  type="email"
                  required
                  className="w-full px-4 py-2 bg-black border-2 border-purple-600 focus:border-purple-400 outline-none"
                  placeholder="hacker@example.com"
                />
              </div>

              {/* Card Number */}
              <div>
                <label className="block text-sm font-bold mb-2 opacity-70">
                  CARD NUMBER
                </label>
                <input
                  type="text"
                  required
                  className="w-full px-4 py-2 bg-black border-2 border-purple-600 focus:border-purple-400 outline-none"
                  placeholder="1234 5678 9012 3456"
                  maxLength={19}
                />
              </div>

              {/* Expiry and CVV */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-bold mb-2 opacity-70">
                    EXPIRY DATE
                  </label>
                  <input
                    type="text"
                    required
                    className="w-full px-4 py-2 bg-black border-2 border-purple-600 focus:border-purple-400 outline-none"
                    placeholder="MM/YY"
                    maxLength={5}
                  />
                </div>
                <div>
                  <label className="block text-sm font-bold mb-2 opacity-70">
                    CVV
                  </label>
                  <input
                    type="text"
                    required
                    className="w-full px-4 py-2 bg-black border-2 border-purple-600 focus:border-purple-400 outline-none"
                    placeholder="123"
                    maxLength={4}
                  />
                </div>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={loading}
                className="w-full py-4 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all glow-purple disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? '[PROCESSING...]' : `[PAY ${planDetails.price}/MONTH]`}
              </button>
            </form>
          </div>
        )}

        {/* Free Plan Activation */}
        {planDetails.price === 'FREE' && (
          <div className="terminal-border bg-black/80 backdrop-blur p-8 mb-8 text-center">
            <p className="text-xl mb-6 opacity-70">
              Ready to activate your FREE plan?
            </p>
            <button
              onClick={handlePayment}
              disabled={loading}
              className="px-8 py-4 bg-green-600 hover:bg-green-500 border-2 border-green-400 font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? '[ACTIVATING...]' : '[ACTIVATE FREE PLAN]'}
            </button>
          </div>
        )}

        {/* Security Notice */}
        <div className="text-center opacity-50 text-sm">
          <p className="mb-2">🔒 Secure payment processing powered by Stripe</p>
          <p>Your payment information is encrypted and secure</p>
        </div>

        {/* Back Button */}
        <div className="text-center mt-8">
          <button
            onClick={() => router.push('/pricing')}
            className="text-purple-400 hover:text-purple-300 underline"
          >
            ← Back to pricing plans
          </button>
        </div>
      </div>
    </div>
  );
}