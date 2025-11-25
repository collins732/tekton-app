'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok) {
        // Redirect to dashboard
        router.push('/dashboard');
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-8">
      <div className="w-full max-w-md">
        <div className="terminal-border bg-black/90 backdrop-blur p-8">
          <h1 className="text-4xl font-bold mb-2 glow-title text-center">[TEKTON]</h1>
          <p className="text-center text-purple-400 mb-8 text-sm">VULNERABILITY SCANNER</p>

          <h2 className="text-2xl font-bold mb-6 glow-header">{'{>'} LOGIN</h2>

          {error && (
            <div className="mb-6 p-4 bg-red-900/20 border-2 border-red-500 text-red-400">
              <span className="font-mono text-sm">[ERROR] {error}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-6">
            <div>
              <label className="block text-sm opacity-50 mb-2">EMAIL</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="your@email.com"
                required
                className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
              />
            </div>

            <div>
              <label className="block text-sm opacity-50 mb-2">PASSWORD</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="w-full bg-black border-2 border-purple-600 px-4 py-3 font-mono focus:outline-none focus:border-purple-400"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-purple-600 hover:bg-purple-500 border-2 border-purple-400 font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? '[LOGGING IN...]' : '[LOGIN]'}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-sm opacity-70">
              Don't have an account?{' '}
              <Link href="/register" className="text-purple-400 hover:text-purple-300 font-bold">
                [REGISTER]
              </Link>
            </p>
          </div>
        </div>

        <div className="mt-4 text-center text-sm opacity-50">
          <p>© 2025 TEKTON - Advanced Security Testing</p>
        </div>
      </div>
    </div>
  );
}
